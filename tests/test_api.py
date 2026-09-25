from __future__ import annotations

import json
import sqlite3
import unittest

from taxonomy_lab.api import JsonApplication
from taxonomy_lab.service import TaxonomyLabService


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

    def test_claim_requires_actor_header(self) -> None:
        response = self.app.handle(
            "POST", "/jobs/claim", body=json.dumps({"worker_id": "w1"}).encode()
        )
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_claim_rejects_role_without_analysis_permission(self) -> None:
        self.app.handle(
            "POST", "/users",
            body=json.dumps({"user_id": "op", "display_name": "操作员", "role": "operator"}).encode(),
        )
        response = self.app.handle(
            "POST", "/jobs/claim", headers={"X-Actor-Id": "op"},
            body=json.dumps({"worker_id": "w1"}).encode(),
        )
        self.assertEqual(response.status, 403)
        self.assertEqual(response.body["error"]["code"], "forbidden")

    def test_claim_rejects_inactive_account(self) -> None:
        self.app.handle(
            "POST", "/users",
            body=json.dumps({"user_id": "st", "display_name": "统计", "role": "statistician"}).encode(),
        )
        self.connection.execute("UPDATE users SET active=0 WHERE user_id='st'")
        response = self.app.handle(
            "POST", "/jobs/claim", headers={"X-Actor-Id": "st"},
            body=json.dumps({"worker_id": "w1"}).encode(),
        )
        self.assertEqual(response.status, 403)

    def test_renew_route_is_guarded_by_actor_and_lease(self) -> None:
        self.app.handle(
            "POST", "/users",
            body=json.dumps({"user_id": "st", "display_name": "统计", "role": "statistician"}).encode(),
        )
        response = self.app.handle(
            "POST", "/jobs/42/renew", headers={"X-Actor-Id": "st"},
            body=json.dumps({"worker_id": "w1", "lease_seconds": 30}).encode(),
        )
        self.assertEqual(response.status, 404)

    def test_audit_events_route_requires_actor(self) -> None:
        response = self.app.handle("GET", "/audit/events")
        self.assertEqual(response.status, 422)


if __name__ == "__main__":
    unittest.main()
