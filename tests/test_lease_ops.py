from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from taxonomy_lab.clock import FrozenClock
from taxonomy_lab.errors import Conflict, Forbidden, InvalidState, NotFound
from taxonomy_lab.jsonio import load_json
from taxonomy_lab.service import TaxonomyLabService
from taxonomy_lab.storage import connect, inspect_schema


ROOT = Path(__file__).resolve().parents[1]


class LeaseTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 22, 0, tzinfo=timezone.utc))
        self.service = TaxonomyLabService(self.connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("stat-2", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.evidence_protocol = load_json(ROOT / "fixtures" / "demo_evidence_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_evidence_items.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_device("operator", "scope-a", "A 型", "厂商")
        self.service.register_build("operator", "build-a", "scope-a", "1.0", "b" * 64)
        self.service.publish_evidence_protocol("stat", self.evidence_protocol)
        self.service.create_batch("operator", "batch-a", "demo-taxonomy-v1", 1, "build-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)

    def tearDown(self) -> None:
        self.connection.close()

    def deactivate(self, user_id: str) -> None:
        self.connection.execute("UPDATE users SET active=0 WHERE user_id=?", (user_id,))

    def queue_events(self, event_type: str) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT * FROM audit_events WHERE entity_type='analysis_queue' AND event_type=? ORDER BY event_id",
            (event_type,),
        ).fetchall()

    def batch_events(self, event_type: str) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT * FROM audit_events WHERE entity_type='batch' AND entity_id='batch-a' AND event_type=? "
            "ORDER BY event_id",
            (event_type,),
        ).fetchall()


class LeaseAuthorizationTests(LeaseTestBase):
    def test_deactivated_account_cannot_claim_and_rejection_is_audited(self) -> None:
        self.deactivate("stat")
        with self.assertRaises(Forbidden):
            self.service.claim_job("stat", "worker-a", 30)
        events = self.queue_events("analysis_job.claim_rejected")
        self.assertEqual(len(events), 1)
        payload = json.loads(events[0]["payload_json"])
        self.assertEqual(payload["worker_id"], "worker-a")
        self.assertIn("停用", payload["reason"])
        self.assertEqual(events[0]["actor_id"], "stat")
        job = self.connection.execute("SELECT * FROM analysis_jobs").fetchone()
        self.assertEqual(job["state"], "queued")
        self.assertIsNone(job["lease_owner"])

    def test_role_without_identification_duty_cannot_claim(self) -> None:
        for actor in ("operator", "approver", "auditor"):
            with self.assertRaises(Forbidden):
                self.service.claim_job(actor, "worker-a", 30)
        self.assertEqual(len(self.queue_events("analysis_job.claim_rejected")), 3)

    def test_unknown_account_cannot_claim(self) -> None:
        with self.assertRaises(NotFound):
            self.service.claim_job("ghost", "worker-a", 30)
        events = self.queue_events("analysis_job.claim_rejected")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["actor_id"], "ghost")

    def test_deactivated_account_cannot_renew_complete_or_fail(self) -> None:
        job = self.service.claim_job("stat", "worker-a", 30)
        self.deactivate("stat")
        with self.assertRaises(Forbidden):
            self.service.renew_job("stat", "worker-a", job["job_id"], job["lease_token"], 30)
        with self.assertRaises(Forbidden):
            self.service.complete_job("stat", "worker-a", job["job_id"], job["lease_token"])
        with self.assertRaises(Forbidden):
            self.service.fail_job("stat", "worker-a", job["job_id"], job["lease_token"], "err")
        for event_type in (
            "analysis_job.renew_rejected",
            "analysis_job.complete_rejected",
            "analysis_job.fail_rejected",
        ):
            self.assertEqual(len(self.queue_events(event_type)), 1, event_type)

    def test_role_without_duty_cannot_fail_someone_elses_lease(self) -> None:
        job = self.service.claim_job("stat", "worker-a", 30)
        with self.assertRaises(Forbidden):
            self.service.fail_job("auditor", "worker-a", job["job_id"], job["lease_token"], "err")
        current = self.connection.execute("SELECT * FROM analysis_jobs").fetchone()
        self.assertEqual(current["state"], "leased")
        self.assertEqual(current["lease_owner"], "worker-a")


class LeaseLifecycleTests(LeaseTestBase):
    def test_claim_binds_operator_and_node_and_audits(self) -> None:
        job = self.service.claim_job("stat", "worker-a", 30)
        self.assertEqual(job["lease_owner"], "worker-a")
        self.assertEqual(job["lease_operator"], "stat")
        self.assertEqual(job["lease_token"], 1)
        self.assertEqual(job["attempts"], 1)
        events = self.batch_events("analysis_job.claimed")
        self.assertEqual(len(events), 1)
        payload = json.loads(events[0]["payload_json"])
        self.assertEqual(payload["operator_id"], "stat")
        self.assertEqual(payload["worker_id"], "worker-a")
        self.assertEqual(payload["lease_token"], 1)
        self.assertEqual(events[0]["actor_id"], "stat")

    def test_repeated_claim_returns_original_lease_state(self) -> None:
        first = self.service.claim_job("stat", "worker-a", 30)
        second = self.service.claim_job("stat", "worker-a", 30)
        self.assertEqual(second["job_id"], first["job_id"])
        self.assertEqual(second["lease_token"], first["lease_token"])
        self.assertEqual(second["lease_expires_at"], first["lease_expires_at"])
        self.assertEqual(second["attempts"], 1)
        # 重复领取不产生新的占用记录
        self.assertEqual(len(self.batch_events("analysis_job.claimed")), 1)

    def test_other_holder_cannot_claim_while_lease_is_live(self) -> None:
        self.service.claim_job("stat", "worker-a", 30)
        self.assertIsNone(self.service.claim_job("stat-2", "worker-b", 30))

    def test_renew_extends_lease_and_rotates_token(self) -> None:
        job = self.service.claim_job("stat", "worker-a", 30)
        self.clock.advance(seconds=10)
        renewed = self.service.renew_job("stat", "worker-a", job["job_id"], job["lease_token"], 60)
        self.assertEqual(renewed["lease_token"], job["lease_token"] + 1)
        self.assertGreater(renewed["lease_expires_at"], job["lease_expires_at"])
        self.assertEqual(renewed["attempts"], 1)
        events = self.batch_events("analysis_job.renewed")
        self.assertEqual(len(events), 1)
        # 旧令牌已失效，不能再用旧令牌完成
        with self.assertRaises(InvalidState):
            self.service.complete_job("stat", "worker-a", job["job_id"], job["lease_token"])
        analysis = self.service.complete_job("stat", "worker-a", job["job_id"], renewed["lease_token"])
        self.assertIn("analysis_id", analysis)

    def test_renew_requires_current_holder(self) -> None:
        job = self.service.claim_job("stat", "worker-a", 30)
        with self.assertRaises(InvalidState):
            self.service.renew_job("stat", "worker-b", job["job_id"], job["lease_token"], 30)
        with self.assertRaises(InvalidState):
            self.service.renew_job("stat-2", "worker-a", job["job_id"], job["lease_token"], 30)
        self.assertEqual(len(self.batch_events("analysis_job.renew_rejected")), 2)

    def test_expired_lease_can_be_taken_over_by_qualified_operator(self) -> None:
        first = self.service.claim_job("stat", "worker-a", 10)
        self.clock.advance(seconds=11)
        second = self.service.claim_job("stat-2", "worker-b", 30)
        self.assertEqual(second["job_id"], first["job_id"])
        self.assertEqual(second["lease_owner"], "worker-b")
        self.assertEqual(second["lease_operator"], "stat-2")
        self.assertEqual(second["lease_token"], first["lease_token"] + 1)
        events = self.batch_events("analysis_job.taken_over")
        self.assertEqual(len(events), 1)
        payload = json.loads(events[0]["payload_json"])
        self.assertEqual(payload["previous_owner"], "worker-a")
        self.assertEqual(payload["previous_operator"], "stat")
        self.assertEqual(payload["operator_id"], "stat-2")
        self.assertIn("过期", payload["reason"])

    def test_late_submission_does_not_overwrite_after_takeover(self) -> None:
        first = self.service.claim_job("stat", "worker-a", 10)
        self.clock.advance(seconds=11)
        second = self.service.claim_job("stat-2", "worker-b", 30)
        # 原持有者迟到完成与迟到失败都被拒绝并留痕
        with self.assertRaises(InvalidState):
            self.service.complete_job("stat", "worker-a", first["job_id"], first["lease_token"])
        with self.assertRaises(InvalidState):
            self.service.fail_job("stat", "worker-a", first["job_id"], first["lease_token"], "迟到失败")
        self.assertEqual(len(self.batch_events("analysis_job.complete_rejected")), 1)
        self.assertEqual(len(self.batch_events("analysis_job.fail_rejected")), 1)
        # 新持有者正常完成，结果不被覆盖
        analysis = self.service.complete_job("stat-2", "worker-b", second["job_id"], second["lease_token"])
        self.assertEqual(analysis["result"]["conclusion"], "pass")
        job = self.connection.execute("SELECT * FROM analysis_jobs").fetchone()
        self.assertEqual(job["state"], "succeeded")
        row = self.connection.execute("SELECT created_by FROM analyses").fetchone()
        self.assertEqual(row["created_by"], "stat-2")

    def test_late_submission_after_expiry_without_takeover_is_rejected(self) -> None:
        first = self.service.claim_job("stat", "worker-a", 10)
        self.clock.advance(seconds=11)
        with self.assertRaises(InvalidState):
            self.service.complete_job("stat", "worker-a", first["job_id"], first["lease_token"])
        events = self.batch_events("analysis_job.complete_rejected")
        self.assertEqual(len(events), 1)
        self.assertIn("过期", json.loads(events[0]["payload_json"])["reason"])

    def test_complete_with_wrong_token_or_node_is_rejected(self) -> None:
        job = self.service.claim_job("stat", "worker-a", 30)
        with self.assertRaises(InvalidState):
            self.service.complete_job("stat", "worker-a", job["job_id"], job["lease_token"] + 9)
        with self.assertRaises(InvalidState):
            self.service.complete_job("stat", "worker-b", job["job_id"], job["lease_token"])
        with self.assertRaises(InvalidState):
            self.service.fail_job("stat", "worker-b", job["job_id"], job["lease_token"], "err")
        current = self.connection.execute("SELECT * FROM analysis_jobs").fetchone()
        self.assertEqual(current["state"], "leased")

    def test_fail_releases_lease_and_audits(self) -> None:
        job = self.service.claim_job("stat", "worker-a", 30)
        failed = self.service.fail_job("stat", "worker-a", job["job_id"], job["lease_token"], "临时计算失败")
        self.assertEqual(failed["state"], "queued")
        events = self.batch_events("analysis_job.failed")
        self.assertEqual(len(events), 1)
        payload = json.loads(events[0]["payload_json"])
        self.assertEqual(payload["operator_id"], "stat")
        self.assertEqual(payload["error"], "临时计算失败")
        current = self.connection.execute("SELECT * FROM analysis_jobs").fetchone()
        self.assertIsNone(current["lease_owner"])
        self.assertIsNone(current["lease_operator"])

    def test_report_exposes_jobs_and_lease_events(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.claim_job("auditor", "worker-x", 30)
        job = self.service.claim_job("stat", "worker-a", 30)
        self.service.complete_job("stat", "worker-a", job["job_id"], job["lease_token"])
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(len(report["jobs"]), 1)
        self.assertEqual(report["jobs"][0]["state"], "succeeded")
        event_types = [event["event_type"] for event in report["events"]]
        self.assertIn("analysis_job.claimed", event_types)
        self.assertIn("analysis_job.completed", event_types)
        queue_types = [event["event_type"] for event in report["queue_events"]]
        self.assertIn("analysis_job.claim_rejected", queue_types)


class LeasePersistenceTests(unittest.TestCase):
    def test_queue_and_audit_survive_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "taxonomy.sqlite3"
            connection = connect(database)
            clock = FrozenClock(datetime(2026, 9, 24, 22, 0, tzinfo=timezone.utc))
            service = TaxonomyLabService(connection, clock)
            service.create_user("operator", "操作员", "operator")
            service.create_user("stat", "统计", "statistician")
            service.create_user("auditor", "审计", "auditor")
            evidence_protocol = load_json(ROOT / "fixtures" / "demo_evidence_protocol.json")
            service.register_device("operator", "scope-a", "A 型", "厂商")
            service.register_build("operator", "build-a", "scope-a", "1.0", "b" * 64)
            service.publish_evidence_protocol("stat", evidence_protocol)
            service.create_batch("operator", "batch-a", "demo-taxonomy-v1", 1, "build-a")
            service.start_batch("operator", "batch-a", 1)
            service.seal_batch("stat", "batch-a", 2)
            claimed = service.claim_job("stat", "worker-a", 30)
            connection.close()

            # 模拟服务重启：新连接、新服务实例，队列与审计必须一致
            reopened = connect(database)
            try:
                restarted = TaxonomyLabService(reopened, clock)
                job = restarted.connection.execute("SELECT * FROM analysis_jobs").fetchone()
                self.assertEqual(job["state"], "leased")
                self.assertEqual(job["lease_owner"], "worker-a")
                self.assertEqual(job["lease_operator"], "stat")
                self.assertEqual(job["lease_token"], claimed["lease_token"])
                # 重启后重复领取仍返回原租约
                again = restarted.claim_job("stat", "worker-a", 30)
                self.assertEqual(again["lease_token"], claimed["lease_token"])
                report = restarted.report("auditor", "batch-a")
                event_types = [event["event_type"] for event in report["events"]]
                self.assertIn("analysis_job.claimed", event_types)
                analysis = restarted.complete_job("stat", "worker-a", job["job_id"], job["lease_token"])
                self.assertIn("analysis_id", analysis)
            finally:
                reopened.close()

    def test_v2_database_is_migrated_without_losing_queue_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "legacy.sqlite3"
            connection = connect(database)
            try:
                # 构造 v2 形态的旧库：analysis_jobs 没有租约追溯列
                connection.executescript(
                    """
                    CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO schema_meta VALUES('schema_version', '2');
                    CREATE TABLE users (
                        user_id TEXT PRIMARY KEY, display_name TEXT NOT NULL,
                        role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
                    );
                    CREATE TABLE batches (batch_id TEXT PRIMARY KEY);
                    CREATE TABLE analysis_jobs (
                        job_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        batch_id TEXT NOT NULL,
                        batch_revision INTEGER NOT NULL,
                        state TEXT NOT NULL,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        available_at TEXT NOT NULL,
                        lease_owner TEXT,
                        lease_expires_at TEXT,
                        last_error TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    INSERT INTO analysis_jobs(batch_id,batch_revision,state,attempts,available_at,
                        lease_owner,lease_expires_at,created_at,updated_at)
                        VALUES('batch-legacy', 2, 'leased', 1, '2026-09-24T00:00:00Z',
                               'worker-old', '2026-09-25T00:00:00Z',
                               '2026-09-24T00:00:00Z', '2026-09-24T00:00:00Z');
                    """
                )
                service = TaxonomyLabService(connection)
                self.assertIsNotNone(service)
                summary = inspect_schema(connection)
                self.assertEqual(summary["schema_version"], "3")
                columns = {
                    row["name"] for row in connection.execute("PRAGMA table_info(analysis_jobs)").fetchall()
                }
                self.assertIn("lease_operator", columns)
                self.assertIn("lease_token", columns)
                job = connection.execute("SELECT * FROM analysis_jobs").fetchone()
                self.assertEqual(job["lease_owner"], "worker-old")
                self.assertEqual(job["lease_token"], 0)
                # 迁移可重复执行
                TaxonomyLabService(connection)
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
