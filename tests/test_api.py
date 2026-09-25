from __future__ import annotations

import json
import sqlite3
import unittest
from pathlib import Path

from taxonomy_lab.api import JsonApplication
from taxonomy_lab.jsonio import load_json
from taxonomy_lab.service import TaxonomyLabService


ROOT = Path(__file__).resolve().parents[1]


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(TaxonomyLabService(self.connection))

    def tearDown(self) -> None:
        self.connection.close()

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_json_error_shape(self) -> None:
        response = self.app.handle("POST", "/users", body=b"not-json")
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_user_route(self) -> None:
        payload = json.dumps({"user_id": "u1", "display_name": "操作员", "role": "operator"}).encode()
        response = self.app.handle("POST", "/users", body=payload)
        self.assertEqual(response.status, 201)
        self.assertEqual(response.body["role"], "operator")


class JobRouteTests(unittest.TestCase):
    """领取、续租、完成与失败接口的鉴权与租约约束。"""

    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.service = TaxonomyLabService(self.connection)
        self.app = JsonApplication(self.service)
        self.service.create_user("operator", "操作员", "operator")
        self.service.create_user("stat", "统计", "statistician")
        self.service.create_user("auditor", "审计", "auditor")
        evidence_protocol = load_json(ROOT / "fixtures" / "demo_evidence_protocol.json")
        self.service.register_device("operator", "scope-a", "A 型", "厂商")
        self.service.register_build("operator", "build-a", "scope-a", "1.0", "b" * 64)
        self.service.publish_evidence_protocol("stat", evidence_protocol)
        self.service.create_batch("operator", "batch-a", "demo-taxonomy-v1", 1, "build-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.seal_batch("stat", "batch-a", 2)

    def tearDown(self) -> None:
        self.connection.close()

    def test_claim_requires_actor_header(self) -> None:
        response = self.app.handle("POST", "/jobs/claim", body=json.dumps({"worker_id": "w1"}).encode())
        self.assertEqual(response.status, 422)

    def test_claim_rejects_role_without_duty_and_is_audited(self) -> None:
        response = self.app.handle(
            "POST", "/jobs/claim", {"X-Actor-Id": "auditor"},
            json.dumps({"worker_id": "w1"}).encode(),
        )
        self.assertEqual(response.status, 403)
        count = self.connection.execute(
            "SELECT count(*) FROM audit_events WHERE event_type='analysis_job.claim_rejected'"
        ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_full_lease_cycle_over_http(self) -> None:
        claim = self.app.handle(
            "POST", "/jobs/claim", {"X-Actor-Id": "stat"},
            json.dumps({"worker_id": "w1", "lease_seconds": 120}).encode(),
        )
        self.assertEqual(claim.status, 200)
        job = claim.body["job"]
        self.assertEqual(job["lease_owner"], "w1")
        self.assertEqual(job["lease_operator"], "stat")
        renew = self.app.handle(
            "POST", f"/jobs/{job['job_id']}/renew", {"X-Actor-Id": "stat"},
            json.dumps({"worker_id": "w1", "lease_token": job["lease_token"], "lease_seconds": 120}).encode(),
        )
        self.assertEqual(renew.status, 200)
        renewed = renew.body["job"]
        self.assertEqual(renewed["lease_token"], job["lease_token"] + 1)
        # 没有观察记录时分析结论为 insufficient，但链路必须完整可走通
        complete = self.app.handle(
            "POST", f"/jobs/{job['job_id']}/complete", {"X-Actor-Id": "stat"},
            json.dumps({"worker_id": "w1", "lease_token": renewed["lease_token"]}).encode(),
        )
        self.assertEqual(complete.status, 200)
        self.assertIn("analysis_id", complete.body)
        # 已完成任务的旧令牌再次提交无效
        replay = self.app.handle(
            "POST", f"/jobs/{job['job_id']}/complete", {"X-Actor-Id": "stat"},
            json.dumps({"worker_id": "w1", "lease_token": renewed["lease_token"]}).encode(),
        )
        self.assertEqual(replay.status, 409)

    def test_fail_route_releases_lease(self) -> None:
        claim = self.app.handle(
            "POST", "/jobs/claim", {"X-Actor-Id": "stat"},
            json.dumps({"worker_id": "w1"}).encode(),
        )
        job = claim.body["job"]
        failed = self.app.handle(
            "POST", f"/jobs/{job['job_id']}/fail", {"X-Actor-Id": "stat"},
            json.dumps({"worker_id": "w1", "lease_token": job["lease_token"], "error": "临时故障"}).encode(),
        )
        self.assertEqual(failed.status, 200)
        self.assertEqual(failed.body["state"], "queued")


if __name__ == "__main__":
    unittest.main()

