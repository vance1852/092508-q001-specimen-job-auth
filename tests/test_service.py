from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from taxonomy_lab.clock import FrozenClock
from taxonomy_lab.errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from taxonomy_lab.jsonio import load_json
from taxonomy_lab.service import TaxonomyLabService
from taxonomy_lab.storage import connect


ROOT = Path(__file__).resolve().parents[1]


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = TaxonomyLabService(self.connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("stat2", "statistician"),
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

    def tearDown(self) -> None:
        self.connection.close()

    def test_complete_workflow(self) -> None:
        imported = self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        self.assertEqual(imported["inserted"], 6)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("stat", "worker", 30)
        analysis = self.service.complete_job("stat", "worker", job["job_id"])
        self.service.decide("approver", "batch-a", analysis["analysis_id"], "approved", "满足规则")
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(report["batch"]["state"], "decided")
        self.assertEqual(report["analysis"]["result"]["conclusion"], "pass")

    def test_idempotent_replay_and_conflict(self) -> None:
        first = self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        second = self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        self.assertEqual(first, second)
        changed = [dict(item) for item in self.rows]
        changed[0] = dict(changed[0])
        changed[0]["indicators"] = dict(changed[0]["indicators"])
        changed[0]["indicators"]["completion_seconds"] = "99"
        with self.assertRaises(Conflict):
            self.service.import_evidence_items("operator", "batch-a", "key-1", changed)
        count = self.connection.execute("SELECT count(*) FROM evidence_items").fetchone()[0]
        self.assertEqual(count, 6)

    def test_import_rolls_back_when_one_source_row_duplicates(self) -> None:
        self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows[:1])
        with self.assertRaises(Conflict):
            self.service.import_evidence_items("operator", "batch-a", "key-2", self.rows[:2])
        count = self.connection.execute("SELECT count(*) FROM evidence_items").fetchone()[0]
        self.assertEqual(count, 1)

    def test_role_separation(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.seal_batch("operator", "batch-a", 2)
        with self.assertRaises(Forbidden):
            self.service.report("operator", "batch-a")

    def test_exclusion_review_and_revoke_leave_history(self) -> None:
        self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        evidence_item_id = self.connection.execute(
            "SELECT evidence_item_id FROM evidence_items ORDER BY evidence_item_id LIMIT 1"
        ).fetchone()[0]
        requested = self.service.request_exclusion("operator", evidence_item_id, "现场记录失效")
        reviewed = self.service.review_exclusion("stat", requested["exclusion_id"], True, "观察材料充分")
        self.assertEqual(reviewed["status"], "approved")
        revoked = self.service.revoke_exclusion("operator", requested["exclusion_id"], "已找回原始记录")
        self.assertEqual(revoked["status"], "revoked")
        events = self.connection.execute(
            "SELECT event_type FROM audit_events WHERE entity_type='evidence_item' AND entity_id=? ORDER BY event_id",
            (str(evidence_item_id),),
        ).fetchall()
        self.assertEqual([row[0] for row in events], ["exclusion.requested", "exclusion.revoked"])

    def test_failed_job_returns_to_queue_after_delay(self) -> None:
        self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("stat", "worker-a", 10)
        failed = self.service.fail_job("stat", "worker-a", job["job_id"], "临时计算失败", retry_seconds=5)
        self.assertEqual(failed["state"], "queued")
        self.assertIsNone(self.service.claim_job("stat", "worker-b", 10))
        self.clock.advance(seconds=5)
        retried = self.service.claim_job("stat", "worker-b", 10)
        self.assertEqual(retried["job_id"], job["job_id"])
        self.assertEqual(retried["attempts"], 2)

    def test_lease_can_be_reclaimed_after_expiry(self) -> None:
        self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)
        first = self.service.claim_job("stat", "worker-a", 10)
        self.clock.advance(seconds=11)
        second = self.service.claim_job("stat", "worker-b", 10)
        self.assertEqual(first["job_id"], second["job_id"])
        self.assertEqual(second["lease_owner"], "worker-b")
        with self.assertRaises(InvalidState):
            self.service.complete_job("stat", "worker-a", first["job_id"])

    def _sealed_job(self) -> dict:
        self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("stat", "worker-a", 10)
        self.assertIsNotNone(job)
        return job

    def _batch_job_events(self) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT event_type,payload_json FROM audit_events "
            "WHERE entity_type='batch' AND entity_id='batch-a' ORDER BY event_id"
        ).fetchall()

    def test_claim_binds_lease_to_operator_and_node(self) -> None:
        job = self._sealed_job()
        self.assertEqual(job["lease_operator"], "stat")
        self.assertEqual(job["lease_owner"], "worker-a")
        stored = self.connection.execute(
            "SELECT lease_operator,lease_owner FROM analysis_jobs WHERE job_id=?", (job["job_id"],)
        ).fetchone()
        self.assertEqual(stored["lease_operator"], "stat")
        events = self._batch_job_events()
        claimed = [json.loads(row["payload_json"]) for row in events if row["event_type"] == "analysis_job.claimed"]
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["operator"], "stat")
        self.assertEqual(claimed[0]["node"], "worker-a")

    def test_claim_requires_analysis_role_and_active_account(self) -> None:
        self._sealed_job()
        with self.assertRaises(Forbidden):
            self.service.claim_job("operator", "worker-x", 10)
        with self.assertRaises(NotFound):
            self.service.claim_job("ghost", "worker-x", 10)
        self.connection.execute("UPDATE users SET active=0 WHERE user_id='stat'")
        with self.assertRaises(Forbidden):
            self.service.claim_job("stat", "worker-x", 10)
        denials = self.connection.execute(
            "SELECT payload_json FROM audit_events WHERE event_type='analysis_job.claim_denied' ORDER BY event_id"
        ).fetchall()
        reasons = [json.loads(row["payload_json"])["reason"] for row in denials]
        self.assertEqual(len(reasons), 3)
        self.assertTrue(all(reasons))

    def test_claim_rejects_blank_node_even_without_touching_queue(self) -> None:
        self._sealed_job()
        with self.assertRaises(ValidationFailed):
            self.service.claim_job("stat", "  ", 10)

    def test_repeat_claim_returns_original_lease_state(self) -> None:
        first = self._sealed_job()
        repeated = self.service.claim_job("stat", "worker-a", 10)
        self.assertEqual(repeated["job_id"], first["job_id"])
        self.assertEqual(repeated["lease_expires_at"], first["lease_expires_at"])
        self.assertEqual(repeated["attempts"], first["attempts"])
        stored = self.connection.execute(
            "SELECT attempts,updated_at FROM analysis_jobs WHERE job_id=?", (first["job_id"],)
        ).fetchone()
        self.assertEqual(stored["attempts"], 1)
        self.assertEqual(stored["updated_at"], first["updated_at"])
        claimed = [row for row in self._batch_job_events() if row["event_type"] == "analysis_job.claimed"]
        self.assertEqual(len(claimed), 1)

    def test_renew_extends_lease_and_is_audited(self) -> None:
        job = self._sealed_job()
        self.clock.advance(seconds=5)
        renewed = self.service.renew_job("stat", "worker-a", job["job_id"], lease_seconds=20)
        self.assertGreater(renewed["lease_expires_at"], job["lease_expires_at"])
        events = self._batch_job_events()
        types = [row["event_type"] for row in events]
        self.assertIn("analysis_job.lease_renewed", types)

    def test_renew_requires_holder_and_unexpired_lease(self) -> None:
        job = self._sealed_job()
        with self.assertRaises(Forbidden):
            self.service.renew_job("operator", "worker-a", job["job_id"], 20)
        with self.assertRaises(InvalidState):
            self.service.renew_job("stat2", "worker-a", job["job_id"], 20)
        with self.assertRaises(InvalidState):
            self.service.renew_job("stat", "worker-other", job["job_id"], 20)
        self.clock.advance(seconds=11)
        with self.assertRaises(InvalidState):
            self.service.renew_job("stat", "worker-a", job["job_id"], 20)
        denied = [
            row for row in self._batch_job_events() if row["event_type"] == "analysis_job.renew_denied"
        ]
        self.assertEqual(len(denied), 4)

    def test_takeover_audited_and_late_submission_does_not_overwrite_result(self) -> None:
        job = self._sealed_job()
        self.clock.advance(seconds=11)
        takeover = self.service.claim_job("stat2", "worker-b", 10)
        self.assertEqual(takeover["job_id"], job["job_id"])
        self.assertEqual(takeover["lease_operator"], "stat2")
        self.assertEqual(takeover["attempts"], 2)
        with self.assertRaises(InvalidState):
            self.service.complete_job("stat", "worker-a", job["job_id"])
        new_analysis = self.service.complete_job("stat2", "worker-b", job["job_id"])
        stored = self.connection.execute(
            "SELECT created_by FROM analyses WHERE analysis_id=?", (new_analysis["analysis_id"],)
        ).fetchone()
        self.assertEqual(stored["created_by"], "stat2")
        events = self._batch_job_events()
        types = [row["event_type"] for row in events]
        self.assertIn("analysis_job.lease_taken_over", types)
        self.assertIn("analysis_job.complete_denied", types)
        self.assertEqual(types.count("analysis.completed"), 1)
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(report["analysis"]["created_by"], "stat2")
        self.assertEqual(report["jobs"][0]["state"], "succeeded")

    def test_fail_requires_role_holder_and_unexpired_lease(self) -> None:
        job = self._sealed_job()
        with self.assertRaises(Forbidden):
            self.service.fail_job("operator", "worker-a", job["job_id"], "无权失败")
        with self.assertRaises(InvalidState):
            self.service.fail_job("stat", "worker-other", job["job_id"], "错误节点")
        self.clock.advance(seconds=11)
        with self.assertRaises(InvalidState):
            self.service.fail_job("stat", "worker-a", job["job_id"], "租约已过期")
        denied = [row for row in self._batch_job_events() if row["event_type"] == "analysis_job.fail_denied"]
        self.assertEqual(len(denied), 3)
        queued_jobs = self.connection.execute("SELECT count(*) FROM analysis_jobs WHERE state='queued'").fetchone()[0]
        self.assertEqual(queued_jobs, 0)

    def test_fail_releases_lease_and_returns_to_queue_with_audit(self) -> None:
        job = self._sealed_job()
        result = self.service.fail_job("stat", "worker-a", job["job_id"], "临时计算失败", retry_seconds=0)
        self.assertEqual(result["state"], "queued")
        events = self._batch_job_events()
        released = [
            json.loads(row["payload_json"])
            for row in events
            if row["event_type"] == "analysis_job.lease_released"
        ]
        self.assertEqual(released[0]["outcome"], "queued")
        self.assertEqual(released[0]["error"], "临时计算失败")

    def test_audit_events_endpoint_requires_audit_permission(self) -> None:
        self._sealed_job()
        with self.assertRaises(Forbidden):
            self.service.audit_events("operator")
        events = self.service.audit_events("auditor", entity_type="batch", entity_id="batch-a")["events"]
        self.assertTrue(any(event["event_type"] == "analysis_job.claimed" for event in events))
        queue_denials = self.service.audit_events(
            "auditor", entity_type="analysis_queue", entity_id="analysis_jobs"
        )["events"]
        self.assertEqual(queue_denials, [])


class RestartConsistencyTests(unittest.TestCase):
    def test_queue_and_audit_survive_restart_from_version_two_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "taxonomy.sqlite3"
            first_connection = connect(database)
            service = TaxonomyLabService(first_connection, FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc)))
            service.create_user("operator", "operator", "operator")
            service.create_user("stat", "stat", "statistician")
            service.create_user("auditor", "auditor", "auditor")
            service.register_device("operator", "scope-a", "A 型", "厂商")
            service.register_build("operator", "build-a", "scope-a", "1.0", "c" * 64)
            service.publish_evidence_protocol("stat", load_json(ROOT / "fixtures" / "demo_evidence_protocol.json"))
            service.create_batch("operator", "batch-a", "demo-taxonomy-v1", 1, "build-a")
            service.start_batch("operator", "batch-a", 1)
            service.import_evidence_items(
                "operator", "batch-a", "key-1",
                [json.loads(line) for line in (ROOT / "fixtures" / "demo_evidence_items.jsonl").read_text().splitlines() if line.strip()],
            )
            service.seal_batch("stat", "batch-a", 2)
            job = service.claim_job("stat", "worker-a", 60)
            service.renew_job("stat", "worker-a", job["job_id"], 120)
            first_connection.close()

            second_connection = connect(database)
            restarted = TaxonomyLabService(second_connection)
            stored_job = second_connection.execute(
                "SELECT lease_operator,lease_owner,state,attempts FROM analysis_jobs WHERE job_id=?",
                (job["job_id"],),
            ).fetchone()
            self.assertEqual(stored_job["lease_operator"], "stat")
            self.assertEqual(stored_job["lease_owner"], "worker-a")
            self.assertEqual(stored_job["state"], "leased")
            self.assertEqual(stored_job["attempts"], 1)
            events = restarted.audit_events("auditor", entity_type="batch", entity_id="batch-a")["events"]
            types = [event["event_type"] for event in events]
            self.assertEqual(types.count("analysis_job.claimed"), 1)
            self.assertEqual(types.count("analysis_job.lease_renewed"), 1)
            self.assertTrue(all("payload" in event for event in events))
            second_connection.close()


if __name__ == "__main__":
    unittest.main()
