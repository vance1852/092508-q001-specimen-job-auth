"""分类实验观察采信服务的领域用例。"""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .analysis import ALGORITHM_VERSION, analyze
from .clock import SystemClock, isoformat
from .contracts import EvidenceItem, EvidenceProtocol, ValidationError
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


ROLE_PERMISSIONS = {
    "operator": {
        "catalog.write", "batch.create", "batch.start", "evidence_item.import",
        "exclusion.request", "exclusion.revoke",
    },
    "statistician": {"evidence_protocol.publish", "batch.seal", "exclusion.review", "analysis.run"},
    "approver": {"decision.write"},
    "auditor": {"report.read", "audit.read"},
}


class TaxonomyLabService:
    """在单个 SQLite 连接上提供全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(payload), self._now()),
        )

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role) VALUES(?,?,?)",
                    (user_id.strip(), display_name.strip(), role),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role}

    def register_device(
        self, actor_id: str, device_id: str, model_name: str, vendor: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO capture_devices(device_id,model_name,vendor,created_at) VALUES(?,?,?,?)",
                    (device_id, model_name, vendor, self._now()),
                )
                self._audit("device", device_id, "device.registered", actor_id, {"model_name": model_name})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"实验采集设备已存在: {device_id}") from exc
        return {"device_id": device_id, "model_name": model_name, "vendor": vendor}

    def register_build(
        self, actor_id: str, build_id: str, device_id: str, version: str, content_sha256: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        if len(content_sha256) != 64:
            raise ValidationFailed("构建摘要必须是 64 位 SHA-256")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO builds(build_id,device_id,version,content_sha256,created_at) VALUES(?,?,?,?,?)",
                    (build_id, device_id, version, content_sha256.lower(), self._now()),
                )
                self._audit("build", build_id, "build.registered", actor_id, {"device_id": device_id, "version": version})
        except sqlite3.IntegrityError as exc:
            raise Conflict("构建编号、版本或摘要冲突") from exc
        return {"build_id": build_id, "device_id": device_id, "version": version}

    def publish_evidence_protocol(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "evidence_protocol.publish")
        try:
            evidence_protocol = EvidenceProtocol.from_dict(raw)
        except ValidationError as exc:
            raise ValidationFailed(str(exc)) from exc
        text = canonical_json(raw)
        digest = content_digest([raw])
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO evidence_protocol_catalog(evidence_protocol_id,version,title,task_family,canonical_json,content_sha256,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        evidence_protocol.evidence_protocol_id,
                        evidence_protocol.version,
                        evidence_protocol.title,
                        evidence_protocol.task_family,
                        text,
                        digest,
                        self._now(),
                    ),
                )
                identity = f"{evidence_protocol.evidence_protocol_id}@{evidence_protocol.version}"
                self._audit("evidence_protocol", identity, "evidence_protocol.published", actor_id, {"sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("协议版本或内容摘要已经存在") from exc
        return {"evidence_protocol_id": evidence_protocol.evidence_protocol_id, "version": evidence_protocol.version, "sha256": digest}

    def _evidence_protocol(self, evidence_protocol_id: str, version: int) -> tuple[EvidenceProtocol, str]:
        row = self.connection.execute(
            "SELECT canonical_json,content_sha256 FROM evidence_protocol_catalog WHERE evidence_protocol_id=? AND version=?",
            (evidence_protocol_id, version),
        ).fetchone()
        if row is None:
            raise NotFound("协议版本不存在")
        return EvidenceProtocol.from_dict(json.loads(row["canonical_json"])), row["content_sha256"]

    def create_batch(
        self,
        actor_id: str,
        batch_id: str,
        evidence_protocol_id: str,
        evidence_protocol_version: int,
        build_id: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "batch.create")
        self._evidence_protocol(evidence_protocol_id, evidence_protocol_version)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO batches(batch_id,evidence_protocol_id,evidence_protocol_version,build_id,state,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (batch_id, evidence_protocol_id, evidence_protocol_version, build_id, "draft", actor_id, self._now()),
                )
                self._audit("batch", batch_id, "batch.created", actor_id, {"build_id": build_id})
        except sqlite3.IntegrityError as exc:
            raise Conflict("批次编号冲突或构建不存在") from exc
        return self.get_batch(batch_id)

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            raise NotFound("批次不存在")
        return dict(row)

    def start_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.start")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE batches SET state='running',revision=revision+1,started_at=? "
                "WHERE batch_id=? AND state='draft' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次不是当前草稿版本")
            self._audit("batch", batch_id, "batch.started", actor_id, {"from_revision": expected_revision})
        return self.get_batch(batch_id)

    def _idempotent_response(self, scope: str, key: str, request_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT request_sha256,response_json FROM idempotency_keys WHERE scope=? AND key=?",
            (scope, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_digest:
            raise Conflict("同一幂等键对应了不同请求内容")
        return json.loads(row["response_json"])

    def import_evidence_items(
        self,
        actor_id: str,
        batch_id: str,
        idempotency_key: str,
        raw_rows: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        self._require(actor_id, "evidence_item.import")
        rows = tuple(raw_rows)
        if not rows:
            raise ValidationFailed("观察记录数组不能为空")
        request_digest = content_digest(rows)
        scope = f"evidence_items:{batch_id}"
        existing = self._idempotent_response(scope, idempotency_key, request_digest)
        if existing is not None:
            return existing
        batch = self.get_batch(batch_id)
        if batch["state"] != "running":
            raise InvalidState("只有运行中的批次可以导入观察记录")
        evidence_protocol, _ = self._evidence_protocol(batch["evidence_protocol_id"], batch["evidence_protocol_version"])
        parsed: list[EvidenceItem] = []
        for raw in rows:
            try:
                item = EvidenceItem.from_dict(raw, evidence_protocol)
            except ValidationError as exc:
                raise ValidationFailed(str(exc)) from exc
            if item.device_id != self.connection.execute(
                "SELECT device_id FROM builds WHERE build_id=?", (batch["build_id"],)
            ).fetchone()["device_id"]:
                raise ValidationFailed("观察记录设备与批次登记不一致")
            parsed.append(item)
        response = {"batch_id": batch_id, "inserted": len(parsed), "request_sha256": request_digest}
        try:
            with transaction(self.connection, immediate=True):
                for item, raw in zip(parsed, rows):
                    self.connection.execute(
                        "INSERT INTO evidence_items(batch_id,source_batch,source_row,device_id,evidence_group_key,observed_at," 
                        "indicators_json,content_sha256,imported_by,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            batch_id,
                            item.source_batch,
                            item.source_row,
                            item.device_id,
                            item.evidence_group_key,
                            item.observed_at,
                            canonical_json({key: format(value, "f") for key, value in item.indicators.items()}),
                            content_digest([raw]),
                            actor_id,
                            self._now(),
                        ),
                    )
                self.connection.execute(
                    "INSERT INTO idempotency_keys(scope,key,request_sha256,response_json,created_at) VALUES(?,?,?,?,?)",
                    (scope, idempotency_key, request_digest, canonical_json(response), self._now()),
                )
                self._audit("batch", batch_id, "evidence_items.imported", actor_id, response)
        except sqlite3.IntegrityError as exc:
            raise Conflict("来源行重复或幂等键并发冲突") from exc
        return response

    def request_exclusion(self, actor_id: str, evidence_item_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.request")
        evidence_item = self.connection.execute(
            "SELECT evidence_item_id,batch_id FROM evidence_items WHERE evidence_item_id=?", (evidence_item_id,)
        ).fetchone()
        if evidence_item is None:
            raise NotFound("观察记录不存在")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO exclusion_requests(evidence_item_id,status,reason,requested_by,requested_at) "
                    "VALUES(?,?,?,?,?)",
                    (evidence_item_id, "pending", reason, actor_id, self._now()),
                )
                exclusion_id = cursor.lastrowid
                self._audit("evidence_item", str(evidence_item_id), "exclusion.requested", actor_id, {"reason": reason})
        except sqlite3.IntegrityError as exc:
            raise Conflict("该观察记录已有待处理或生效排除") from exc
        return {"exclusion_id": exclusion_id, "status": "pending"}

    def review_exclusion(
        self, actor_id: str, exclusion_id: int, approve: bool, note: str
    ) -> dict[str, Any]:
        self._require(actor_id, "exclusion.review")
        row = self.connection.execute(
            "SELECT * FROM exclusion_requests WHERE exclusion_id=?", (exclusion_id,)
        ).fetchone()
        if row is None:
            raise NotFound("排除申请不存在")
        if row["status"] != "pending":
            raise InvalidState("排除申请已经处理")
        if row["requested_by"] == actor_id:
            raise Forbidden("申请人不能复核自己的排除申请")
        status = "approved" if approve else "rejected"
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE exclusion_requests SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE exclusion_id=? AND status='pending'",
                (status, actor_id, self._now(), note, exclusion_id),
            )
            self._audit("exclusion", str(exclusion_id), f"exclusion.{status}", actor_id, {"note": note})
        return {"exclusion_id": exclusion_id, "status": status}

    def revoke_exclusion(self, actor_id: str, exclusion_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.revoke")
        row = self.connection.execute(
            "SELECT e.*,o.batch_id FROM exclusion_requests e "
            "JOIN evidence_items o ON o.evidence_item_id=e.evidence_item_id WHERE e.exclusion_id=?",
            (exclusion_id,),
        ).fetchone()
        if row is None:
            raise NotFound("排除记录不存在")
        if row["status"] != "approved":
            raise InvalidState("只有已批准的排除可以撤销")
        if row["requested_by"] != actor_id:
            raise Forbidden("只有原申请人可以撤销排除")
        batch = self.get_batch(row["batch_id"])
        if batch["state"] != "running":
            raise InvalidState("批次封存后不能改变排除状态")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE exclusion_requests SET status='revoked',review_note=?,reviewed_at=? "
                "WHERE exclusion_id=? AND status='approved'",
                (reason, self._now(), exclusion_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("排除状态已变化")
            self._audit(
                "evidence_item",
                str(row["evidence_item_id"]),
                "exclusion.revoked",
                actor_id,
                {"exclusion_id": exclusion_id, "reason": reason},
            )
        return {"exclusion_id": exclusion_id, "status": "revoked"}

    def seal_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.seal")
        with transaction(self.connection, immediate=True):
            pending = self.connection.execute(
                "SELECT count(*) FROM exclusion_requests e JOIN evidence_items o ON o.evidence_item_id=e.evidence_item_id "
                "WHERE o.batch_id=? AND e.status='pending'", (batch_id,)
            ).fetchone()[0]
            if pending:
                raise InvalidState("仍有待复核的排除申请")
            cursor = self.connection.execute(
                "UPDATE batches SET state='sealed',revision=revision+1,sealed_at=? "
                "WHERE batch_id=? AND state='running' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次状态或版本已变化")
            new_revision = expected_revision + 1
            now = self._now()
            self.connection.execute(
                "INSERT INTO analysis_jobs(batch_id,batch_revision,state,available_at,created_at,updated_at) "
                "VALUES(?,?, 'queued', ?,?,?)",
                (batch_id, new_revision, now, now, now),
            )
            self._audit("batch", batch_id, "batch.sealed", actor_id, {"revision": new_revision})
        return self.get_batch(batch_id)

    QUEUE_ENTITY_TYPE = "analysis_queue"
    QUEUE_ENTITY_ID = "analysis_jobs"

    def _require_lease_operator(self, actor_id: str) -> sqlite3.Row:
        """领取链路统一入口：账号必须存在、未停用且具备鉴定职责。"""

        return self._require(actor_id, "analysis.run")

    def _audit_lease_rejection(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        """拒绝也必须留痕：在独立事务中记录，随后再抛出原错误。"""

        with transaction(self.connection, immediate=True):
            self._audit(entity_type, entity_id, event_type, actor_id, payload)

    def _require_queue_access(self, event_type: str, actor_id: str, payload: Mapping[str, Any]) -> None:
        try:
            self._require_lease_operator(actor_id)
        except (NotFound, Forbidden) as exc:
            self._audit_lease_rejection(
                self.QUEUE_ENTITY_TYPE, self.QUEUE_ENTITY_ID, event_type, actor_id,
                {**payload, "reason": str(exc)},
            )
            raise

    def claim_job(self, actor_id: str, worker_id: str, lease_seconds: int = 60) -> dict[str, Any] | None:
        if not worker_id or not worker_id.strip():
            raise ValidationFailed("工作节点编号不能为空")
        worker_id = worker_id.strip()
        if lease_seconds <= 0:
            raise ValidationFailed("租约时长必须大于零")
        self._require_queue_access(
            "analysis_job.claim_rejected", actor_id, {"worker_id": worker_id}
        )
        now = self._now()
        expires = isoformat(self.clock.now() + timedelta(seconds=lease_seconds))
        with transaction(self.connection, immediate=True):
            held = self.connection.execute(
                "SELECT * FROM analysis_jobs WHERE state='leased' AND lease_owner=? AND lease_operator=? "
                "AND lease_expires_at>? ORDER BY job_id LIMIT 1",
                (worker_id, actor_id, now),
            ).fetchone()
            if held is not None:
                # 重复领取同一租约：不改变任何状态，直接返回原租约。
                return dict(held)
            row = self.connection.execute(
                "SELECT * FROM analysis_jobs WHERE "
                "(state='queued' AND available_at<=?) OR (state='leased' AND lease_expires_at<=?) "
                "ORDER BY available_at,job_id LIMIT 1",
                (now, now),
            ).fetchone()
            if row is None:
                return None
            cursor = self.connection.execute(
                "UPDATE analysis_jobs SET state='leased',attempts=attempts+1,lease_owner=?,lease_operator=?,"
                "lease_token=lease_token+1,lease_expires_at=?,updated_at=? "
                "WHERE job_id=? AND ((state='queued' AND available_at<=?) OR (state='leased' AND lease_expires_at<=?))",
                (worker_id, actor_id, expires, now, row["job_id"], now, now),
            )
            if cursor.rowcount != 1:
                raise Conflict("分析任务状态已变化，请重新领取")
            claimed = self.connection.execute(
                "SELECT * FROM analysis_jobs WHERE job_id=?", (row["job_id"],)
            ).fetchone()
            payload: dict[str, Any] = {
                "job_id": row["job_id"],
                "worker_id": worker_id,
                "operator_id": actor_id,
                "lease_token": claimed["lease_token"],
                "lease_expires_at": expires,
                "attempt": claimed["attempts"],
            }
            if row["state"] == "leased" and (
                row["lease_owner"] != worker_id or row["lease_operator"] != actor_id
            ):
                event_type = "analysis_job.taken_over"
                payload.update({
                    "previous_owner": row["lease_owner"],
                    "previous_operator": row["lease_operator"],
                    "previous_lease_token": row["lease_token"],
                    "reason": "原租约已过期，由合格人员接管",
                })
            else:
                event_type = "analysis_job.claimed"
            self._audit("batch", row["batch_id"], event_type, actor_id, payload)
        return dict(claimed)

    def _lease_rejection_reason(
        self, job: sqlite3.Row, actor_id: str, worker_id: str, lease_token: int
    ) -> str | None:
        if job["state"] != "leased":
            return f"任务当前状态为 {job['state']}，不在租约中"
        if job["lease_owner"] != worker_id or job["lease_operator"] != actor_id:
            return "任务未由当前操作者与节点持有"
        if job["lease_token"] != lease_token:
            return "租约令牌已变更，任务可能已被接管"
        if job["lease_expires_at"] <= self._now():
            return "任务租约已经过期"
        return None

    def _leased_job(
        self, event_type: str, actor_id: str, worker_id: str, job_id: int, lease_token: int
    ) -> sqlite3.Row:
        """校验操作者身份与租约 fencing；拒绝时留痕并抛出。"""

        self._require_queue_access(
            event_type, actor_id, {"job_id": job_id, "worker_id": worker_id}
        )
        job = self.connection.execute(
            "SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        if job is None:
            raise NotFound("分析任务不存在")
        reason = self._lease_rejection_reason(job, actor_id, worker_id, lease_token)
        if reason is not None:
            self._audit_lease_rejection(
                "batch", job["batch_id"], event_type, actor_id,
                {"job_id": job_id, "worker_id": worker_id, "lease_token": lease_token, "reason": reason},
            )
            raise InvalidState(reason)
        return job

    def renew_job(
        self, actor_id: str, worker_id: str, job_id: int, lease_token: int, lease_seconds: int = 60
    ) -> dict[str, Any]:
        if lease_seconds <= 0:
            raise ValidationFailed("租约时长必须大于零")
        job = self._leased_job("analysis_job.renew_rejected", actor_id, worker_id, job_id, lease_token)
        now = self._now()
        expires = isoformat(self.clock.now() + timedelta(seconds=lease_seconds))
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE analysis_jobs SET lease_expires_at=?,lease_token=lease_token+1,updated_at=? "
                "WHERE job_id=? AND state='leased' AND lease_owner=? AND lease_operator=? "
                "AND lease_token=? AND lease_expires_at>?",
                (expires, now, job_id, worker_id, actor_id, lease_token, now),
            )
            if cursor.rowcount != 1:
                raise InvalidState("任务租约已变化，无法续租")
            renewed = self.connection.execute(
                "SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            self._audit("batch", job["batch_id"], "analysis_job.renewed", actor_id, {
                "job_id": job_id,
                "worker_id": worker_id,
                "operator_id": actor_id,
                "lease_token": renewed["lease_token"],
                "lease_expires_at": expires,
            })
        return dict(renewed)

    def _analysis_evidence_items(self, batch_id: str, evidence_protocol: EvidenceProtocol) -> tuple[EvidenceItem, ...]:
        rows = self.connection.execute(
            "SELECT o.*,e.reason AS excluded_reason FROM evidence_items o "
            "LEFT JOIN exclusion_requests e ON e.evidence_item_id=o.evidence_item_id AND e.status='approved' "
            "WHERE o.batch_id=? ORDER BY o.evidence_item_id",
            (batch_id,),
        ).fetchall()
        items: list[EvidenceItem] = []
        for row in rows:
            indicators = json.loads(row["indicators_json"])
            items.append(EvidenceItem(
                source_batch=row["source_batch"],
                source_row=row["source_row"],
                device_id=row["device_id"],
                evidence_protocol_id=evidence_protocol.evidence_protocol_id,
                evidence_protocol_version=evidence_protocol.version,
                evidence_group_key=row["evidence_group_key"],
                observed_at=row["observed_at"],
                indicators={key: Decimal(str(value)) for key, value in indicators.items()},
                excluded_reason=row["excluded_reason"],
            ))
        return tuple(items)

    def complete_job(self, actor_id: str, worker_id: str, job_id: int, lease_token: int) -> dict[str, Any]:
        job = self._leased_job("analysis_job.complete_rejected", actor_id, worker_id, job_id, lease_token)
        batch = self.get_batch(job["batch_id"])
        evidence_protocol, evidence_protocol_digest = self._evidence_protocol(batch["evidence_protocol_id"], batch["evidence_protocol_version"])
        evidence_items = self._analysis_evidence_items(batch["batch_id"], evidence_protocol)
        snapshot_rows = [
            {
                "source_batch": item.source_batch,
                "source_row": item.source_row,
                "evidence_group": item.evidence_group_key,
                "indicators": {key: format(value, "f") for key, value in item.indicators.items()},
                "excluded_reason": item.excluded_reason,
            }
            for item in evidence_items
        ]
        input_digest = content_digest(snapshot_rows)
        result = analyze(evidence_protocol, evidence_items)
        with transaction(self.connection, immediate=True):
            existing = self.connection.execute(
                "SELECT analysis_id,result_json FROM analyses WHERE batch_id=? AND batch_revision=? AND input_sha256=?",
                (batch["batch_id"], job["batch_revision"], input_digest),
            ).fetchone()
            if existing is None:
                cursor = self.connection.execute(
                    "INSERT INTO analyses(batch_id,batch_revision,evidence_protocol_sha256,input_sha256,algorithm_version,seed,"
                    "result_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        batch["batch_id"], job["batch_revision"], evidence_protocol_digest, input_digest,
                        ALGORITHM_VERSION, evidence_protocol.seed, canonical_json(result), actor_id, self._now(),
                    ),
                )
                analysis_id = cursor.lastrowid
            else:
                analysis_id = existing["analysis_id"]
                result = json.loads(existing["result_json"])
            cursor = self.connection.execute(
                "UPDATE analysis_jobs SET state='succeeded',lease_owner=NULL,lease_operator=NULL,lease_expires_at=NULL,"
                "updated_at=? WHERE job_id=? AND state='leased' AND lease_owner=? AND lease_operator=? AND lease_token=?",
                (self._now(), job_id, worker_id, actor_id, lease_token),
            )
            if cursor.rowcount != 1:
                raise InvalidState("任务租约已变化，迟到提交不能覆盖当前结果")
            self.connection.execute(
                "UPDATE batches SET state='analyzed' WHERE batch_id=? AND state IN ('sealed','analyzing')",
                (batch["batch_id"],),
            )
            self._audit(
                "batch",
                batch["batch_id"],
                "analysis_job.completed",
                actor_id,
                {
                    "job_id": job_id,
                    "worker_id": worker_id,
                    "operator_id": actor_id,
                    "lease_token": lease_token,
                    "analysis_id": analysis_id,
                    "input_sha256": input_digest,
                },
            )
        return {"analysis_id": analysis_id, "input_sha256": input_digest, "result": result}

    def fail_job(
        self,
        actor_id: str,
        worker_id: str,
        job_id: int,
        lease_token: int,
        error: str,
        retry_seconds: int = 0,
    ) -> dict[str, Any]:
        if retry_seconds < 0:
            raise ValidationFailed("重试延迟不能为负数")
        self._require_queue_access(
            "analysis_job.fail_rejected", actor_id, {"job_id": job_id, "worker_id": worker_id}
        )
        job = self.connection.execute(
            "SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        if job is None:
            raise NotFound("分析任务不存在")
        # 失败只释放租约、不写入结果，因此过期本身不拒绝；令牌 fencing 已保证
        # 迟到失败不会清理接管者的新租约。
        if (
            job["state"] != "leased"
            or job["lease_owner"] != worker_id
            or job["lease_operator"] != actor_id
            or job["lease_token"] != lease_token
        ):
            reason = "任务未由当前操作者与节点持有，或租约令牌已变更"
            self._audit_lease_rejection(
                "batch", job["batch_id"], "analysis_job.fail_rejected", actor_id,
                {"job_id": job_id, "worker_id": worker_id, "lease_token": lease_token, "reason": reason},
            )
            raise InvalidState(reason)
        available = isoformat(self.clock.now() + timedelta(seconds=retry_seconds))
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE analysis_jobs SET state='queued',available_at=?,lease_owner=NULL,lease_operator=NULL,"
                "lease_expires_at=NULL,last_error=?,updated_at=? "
                "WHERE job_id=? AND state='leased' AND lease_owner=? AND lease_operator=? AND lease_token=?",
                (available, error[:1000], self._now(), job_id, worker_id, actor_id, lease_token),
            )
            if cursor.rowcount != 1:
                raise InvalidState("任务租约已变化，无法释放")
            self._audit("batch", job["batch_id"], "analysis_job.failed", actor_id, {
                "job_id": job_id,
                "worker_id": worker_id,
                "operator_id": actor_id,
                "lease_token": lease_token,
                "error": error[:1000],
                "retry_seconds": retry_seconds,
                "available_at": available,
            })
        return {"job_id": job_id, "state": "queued", "available_at": available}

    def decide(
        self, actor_id: str, batch_id: str, analysis_id: int, decision: str, reason: str
    ) -> dict[str, Any]:
        self._require(actor_id, "decision.write")
        if decision not in {"needs_more_data", "approved", "rejected"}:
            raise ValidationFailed("未知观察材料采信决定")
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE analysis_id=? AND batch_id=?", (analysis_id, batch_id)
        ).fetchone()
        if analysis_row is None:
            raise NotFound("分析版本不存在")
        if analysis_row["created_by"] == actor_id:
            raise Forbidden("统计负责人不能批准自己的分析")
        batch = self.get_batch(batch_id)
        if batch["state"] != "analyzed" or batch["revision"] != analysis_row["batch_revision"]:
            raise InvalidState("分析不是批次当前可审批版本")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO decisions(batch_id,analysis_id,decision,reason,decided_by,decided_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (batch_id, analysis_id, decision, reason, actor_id, self._now()),
                )
                self.connection.execute("UPDATE batches SET state='decided' WHERE batch_id=?", (batch_id,))
                self._audit(
                    "batch",
                    batch_id,
                    "decision.recorded",
                    actor_id,
                    {"decision_id": cursor.lastrowid, "analysis_id": analysis_id, "decision": decision},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该分析版本已经形成决定") from exc
        return {"batch_id": batch_id, "analysis_id": analysis_id, "decision": decision}

    def report(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        user = self._user(actor_id)
        if user["role"] not in {"statistician", "approver", "auditor"}:
            raise Forbidden("当前角色不能读取完整报告")
        batch = self.get_batch(batch_id)
        evidence_protocol, evidence_protocol_digest = self._evidence_protocol(batch["evidence_protocol_id"], batch["evidence_protocol_version"])
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE batch_id=? ORDER BY analysis_id DESC LIMIT 1", (batch_id,)
        ).fetchone()
        decision_row = None
        if analysis_row is not None:
            decision_row = self.connection.execute(
                "SELECT * FROM decisions WHERE analysis_id=?", (analysis_row["analysis_id"],)
            ).fetchone()
        exclusions = self.connection.execute(
            "SELECT e.exclusion_id,e.evidence_item_id,e.status,e.reason,e.requested_by,e.reviewed_by "
            "FROM exclusion_requests e JOIN evidence_items o ON o.evidence_item_id=e.evidence_item_id "
            "WHERE o.batch_id=? ORDER BY e.exclusion_id", (batch_id,)
        ).fetchall()
        events = self.connection.execute(
            "SELECT event_type,actor_id,payload_json,created_at FROM audit_events "
            "WHERE entity_type='batch' AND entity_id=? "
            "ORDER BY event_id", (batch_id,)
        ).fetchall()
        jobs = self.connection.execute(
            "SELECT * FROM analysis_jobs WHERE batch_id=? ORDER BY job_id", (batch_id,)
        ).fetchall()
        queue_events = self.connection.execute(
            "SELECT event_type,actor_id,payload_json,created_at FROM audit_events "
            "WHERE entity_type=? ORDER BY event_id", (self.QUEUE_ENTITY_TYPE,)
        ).fetchall()
        return {
            "batch": batch,
            "evidence_protocol": {
                "evidence_protocol_id": evidence_protocol.evidence_protocol_id,
                "version": evidence_protocol.version,
                "sha256": evidence_protocol_digest,
                "seed": evidence_protocol.seed,
                "bootstrap_samples": evidence_protocol.bootstrap_samples,
            },
            "analysis": None if analysis_row is None else {
                "analysis_id": analysis_row["analysis_id"],
                "input_sha256": analysis_row["input_sha256"],
                "algorithm_version": analysis_row["algorithm_version"],
                "created_by": analysis_row["created_by"],
                "result": json.loads(analysis_row["result_json"]),
            },
            "decision": None if decision_row is None else dict(decision_row),
            "exclusions": [dict(row) for row in exclusions],
            "jobs": [dict(row) for row in jobs],
            "events": [dict(row) | {"payload": json.loads(row["payload_json"])} for row in events],
            "queue_events": [dict(row) | {"payload": json.loads(row["payload_json"])} for row in queue_events],
        }
