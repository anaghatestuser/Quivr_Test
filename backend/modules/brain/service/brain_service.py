# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    hop_label = source_type + "->" + destination_type
    # A genuine policy block stops later checks in the same request context only
    # (a contextvar, not process-wide) so one blocked call never breaks the next request.
    _latch = getattr(gr_check, "_latch", None)
    if _latch is None:
        import contextvars as _cv
        _latch = gr_check._latch = _cv.ContextVar("lineaje_gr_blocked", default=None)
    _prior = _latch.get()
    if _prior:
        _log.warning("gr_client[%s]: skipping POST /enforce — request already blocked (%s)", hop_label, _prior[1])
        raise GRBlockedError(_prior[0], _prior[1])
    def _blk(o):
        if isinstance(o, dict):
            return any(_blk(o.get(k)) for k in ("skill_path", "skill_file", "path", "file_path", "data", "skill_manifest_path"))
        s = str(o or "")
        b = s.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if b.endswith(".md.blocked"): return True
        try:
            if b in ("skill.md", "skills.md") and _os.path.isfile(str(o) + ".blocked"): return True
        except Exception:
            pass
        return False
    if _blk(data) or _blk(context):
        _log.warning("gr_client[%s]: quarantined skill (*.blocked) — not loaded, GR not called", hop_label)
        _latch.set(("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded"))
        raise GRBlockedError("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded")
    def _stub_client():
        # gr_stub_client.py (shipped next to instrumented files) loads .env, exchanges
        # the refresh token, and re-registers the site on unknown_site /
        # candidate_policies_mismatch — prefer it over the bare POST below.
        import sys as _s, importlib.util as _ilu
        from pathlib import Path as _P
        n = "_lineaje_gr_stub_client"
        if n in _s.modules: return _s.modules[n]
        if getattr(gr_check, "_no_stub_client", False): return None
        try:
            h = _P(__file__).resolve().parent
            c = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), None)
            if c is not None:
                spec = _ilu.spec_from_file_location(n, c)
                _s.modules[n] = m = _ilu.module_from_spec(spec)
                spec.loader.exec_module(m)
                if hasattr(m, "check") and hasattr(m, "SiteDescriptor"): return m
                _s.modules.pop(n, None)
        except Exception as exc:
            _s.modules.pop(n, None)
            _log.warning("gr_client[%s]: gr_stub_client.py not loadable (%s) — using inline client", hop_label, exc)
        gr_check._no_stub_client = True
        return None
    def _block(policy_id, reason):
        _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
        if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
            return data
        _latch.set((policy_id, reason))
        raise GRBlockedError(policy_id, reason)
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    _sc = _stub_client()
    if _sc is not None:
        try:
            _cp = [p if isinstance(p, dict) else {"policy_id": p} for p in (context.get("candidate_policies") or [])]
            _site = _sc.SiteDescriptor(site_id=context.get("site_id") or "", candidate_policies=_cp, fail_mode="BLOCK", source_type=source_type, destination_type=destination_type)
            _d = _sc.check(_site, data, tenant_id=tid, timeout=timeout)
        except Exception as exc:
            _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
            return data
        if _d.blocked and not getattr(_d, "infra_failure", False):
            _acts = _d.actions_applied or []
            _pid = (_acts[0].get("policy_id") if _acts and isinstance(_acts[0], dict) else "") or "unknown"
            return _block(_pid, _d.warning or "Request denied by policy enforcement.")
        if _d.blocked:
            _log.warning("gr_client[%s]: GR service unavailable (%s) — failing open", hop_label, _d.warning)
            return data
        return data if _d.payload is None else _d.payload
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data
    # Refresh token first: the GR service exchanges it for the access JWT it
    # calls the Data Service policy API with; a lineaje_pat_ PAT only
    # identifies the caller and cannot be exchanged.
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_REFRESH_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    params_key = "out_params" if destination_type == "agent" else "in_params"
    def _gr_js(o):
        # JSON form of non-JSON payloads (LangChain Document, pydantic models, ...).
        if hasattr(o, "page_content"):
            return {"page_content": o.page_content, "metadata": getattr(o, "metadata", None) or {}}
        for _m in ("model_dump", "dict", "to_dict"):
            _f = getattr(o, _m, None)
            if callable(_f):
                try:
                    return _f()
                except Exception:
                    pass
        if isinstance(o, (set, tuple)):
            return list(o)
        return str(o)
    def _gr_back(orig, new):
        # Map the (possibly masked) JSON back onto the caller's own objects.
        if new == _j.loads(_j.dumps(orig, default=_gr_js)):
            return orig
        if isinstance(orig, (list, tuple)) and isinstance(new, list) and len(orig) == len(new):
            _out = [_gr_back(a, b) for a, b in zip(orig, new)]
            return tuple(_out) if isinstance(orig, tuple) else _out
        if hasattr(orig, "page_content") and isinstance(new, dict) and "page_content" in new:
            import copy as _cp
            _c = _cp.copy(orig)
            _c.page_content = new["page_content"]
            if isinstance(new.get("metadata"), dict) and hasattr(_c, "metadata"):
                _c.metadata = new["metadata"]
            return _c
        if orig is None or isinstance(orig, (str, int, float, bool, dict, list)):
            return new
        _log.warning("gr_client[%s]: masked result cannot be applied to %s — returning original", hop_label, type(orig).__name__)
        return orig
    _base = url.rstrip("/")
    if _base.lower().endswith("/enforce"): _base = _base[: -len("/enforce")].rstrip("/")
    def _post(body):
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        req = _ur.Request(_base + "/enforce", data=_j.dumps(body, default=_gr_js).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            return _j.loads(resp.read())
    try:
        _sent = _j.loads(_j.dumps(data, default=_gr_js))
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": _sent}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
    except Exception as exc:
        _log.warning("gr_client[%s]: payload not serializable (%s) — failing open", hop_label, exc)
        return data
    result = None
    for _attempt in (0, 1):
        try:
            result = _post(body)
            break
        except Exception as exc:
            if isinstance(exc, _ue.HTTPError) and exc.code == 403:
                try: detail = _j.loads(exc.read()).get("detail", {})
                except Exception: detail = {}
                if not isinstance(detail, dict): detail = {"message": str(detail)}
                blocked_by = detail.get("blocked_by") or []
                if blocked_by or detail.get("error") == "request_blocked":
                    _pid = (blocked_by[0].get("policy_id") if isinstance(blocked_by[0], dict) else "") if blocked_by else ""
                    return _block(_pid or "unknown", detail.get("message", "Request denied by policy enforcement."))
                if _attempt == 0 and (body.get("site_id") or body.get("candidate_policies")):
                    # unknown_site / candidate_policies_mismatch: a site-manifest
                    # problem, not a policy verdict — re-evaluate without site scoping.
                    _log.warning("gr_client[%s]: %s — retrying without site_id", hop_label, detail.get("error") or detail.get("message") or "403")
                    body = {k: v for k, v in body.items() if k not in ("site_id", "candidate_policies")}
                    continue
            _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
            return data
    if not isinstance(result, dict):
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    if not isinstance(result.get("result"), dict) or "data" not in result["result"]:
        return data
    return _gr_back(data, result["result"]["data"])
from typing import Optional
from uuid import UUID

from fastapi import HTTPException
from modules.brain.dto.inputs import BrainUpdatableProperties, CreateBrainProperties
from modules.brain.entity.brain_entity import BrainEntity, BrainType, PublicBrain
from modules.brain.repository import (
    Brains,
    BrainsUsers,
    BrainsVectors,
    CompositeBrainsConnections,
    ExternalApiSecrets,
)
from modules.brain.repository.interfaces import (
    BrainsInterface,
    BrainsUsersInterface,
    BrainsVectorsInterface,
    CompositeBrainsConnectionsInterface,
    ExternalApiSecretsInterface,
)
from modules.brain.service.api_brain_definition_service import ApiBrainDefinitionService
from modules.brain.service.utils.validate_brain import validate_api_brain
from modules.knowledge.service.knowledge_service import KnowledgeService

knowledge_service = KnowledgeService()
# TODO: directly user api_brain_definition repository
api_brain_definition_service = ApiBrainDefinitionService()


class BrainService:
    brain_repository: BrainsInterface
    brain_user_repository: BrainsUsersInterface
    brain_vector_repository: BrainsVectorsInterface
    external_api_secrets_repository: ExternalApiSecretsInterface
    composite_brains_connections_repository: CompositeBrainsConnectionsInterface

    def __init__(self):
        self.brain_repository = Brains()
        self.brain_user_repository = BrainsUsers()
        self.brain_vector = BrainsVectors()
        self.external_api_secrets_repository = ExternalApiSecrets()
        self.composite_brains_connections_repository = CompositeBrainsConnections()

    def get_brain_by_id(self, brain_id: UUID):
        return self.brain_repository.get_brain_by_id(brain_id)

    def create_brain(
        self,
        user_id: UUID,
        brain: Optional[CreateBrainProperties],
    ) -> BrainEntity:
        if brain == None:
            brain = CreateBrainProperties()  # type: ignore model and brain_definition

        if brain.brain_type == BrainType.API:
            validate_api_brain(brain)
            return self.create_brain_api(user_id, brain)

        if brain.brain_type == BrainType.COMPOSITE:
            return self.create_brain_composite(brain)

        created_brain = self.brain_repository.create_brain(brain)
        try:
            created_brain = gr_check(created_brain, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:2a8b5fdbc7edf6e94c2f1c7d6888a17d578fc3101600a412fbe40c94ddc74bbf')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            created_brain = created_brain
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return created_brain

    def create_brain_api(
        self,
        user_id: UUID,
        brain: CreateBrainProperties,
    ) -> BrainEntity:
        created_brain = self.brain_repository.create_brain(brain)

        if brain.brain_definition is not None:
            api_brain_definition_service.add_api_brain_definition(
                brain_id=created_brain.brain_id,
                api_brain_definition=brain.brain_definition,
            )

        secrets_values = brain.brain_secrets_values

        for secret_name in secrets_values:
            self.external_api_secrets_repository.create_secret(
                user_id=user_id,
                brain_id=created_brain.brain_id,
                secret_name=secret_name,
                secret_value=secrets_values[secret_name],
            )

        try:
            created_brain = gr_check(created_brain, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:919f6b5d8c5c52d0757a19eeb4527f49bf7a99be36345758f1da1155b6fe728c')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            created_brain = created_brain
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return created_brain

    def create_brain_composite(
        self,
        brain: CreateBrainProperties,
    ) -> BrainEntity:
        created_brain = self.brain_repository.create_brain(brain)

        if brain.connected_brains_ids is not None:
            for connected_brain_id in brain.connected_brains_ids:
                self.composite_brains_connections_repository.connect_brain(
                    composite_brain_id=created_brain.brain_id,
                    connected_brain_id=connected_brain_id,
                )

        try:
            created_brain = gr_check(created_brain, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:ee75aea85591b125297dbb212b780b9b24917fc43ca93aa0d4ba2adff7c863a1')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            created_brain = created_brain
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return created_brain

    def delete_brain_secrets_values(self, brain_id: UUID) -> None:
        brain_definition = api_brain_definition_service.get_api_brain_definition(
            brain_id=brain_id
        )

        if brain_definition is None:
            raise HTTPException(status_code=404, detail="Brain definition not found.")

        secrets = brain_definition.secrets

        if len(secrets) > 0:
            brain_users = self.brain_user_repository.get_brain_users(brain_id=brain_id)
            for user in brain_users:
                for secret in secrets:
                    self.external_api_secrets_repository.delete_secret(
                        user_id=user.user_id,
                        brain_id=brain_id,
                        secret_name=secret.name,
                    )

    def delete_brain(self, brain_id: UUID) -> dict[str, str]:
        brain_to_delete = self.get_brain_by_id(brain_id=brain_id)
        if brain_to_delete is None:
            raise HTTPException(status_code=404, detail="Brain not found.")

        if brain_to_delete.brain_type == BrainType.API:
            self.delete_brain_secrets_values(
                brain_id=brain_id,
            )
            api_brain_definition_service.delete_api_brain_definition(brain_id=brain_id)
        else:
            knowledge_service.remove_brain_all_knowledge(brain_id)

        self.brain_vector.delete_brain_vector(str(brain_id))
        self.brain_user_repository.delete_brain_users(str(brain_id))
        self.brain_repository.delete_brain(str(brain_id))  # type: ignore

        return {"message": "Brain deleted."}

    def get_brain_prompt_id(self, brain_id: UUID) -> UUID | None:
        brain = self.get_brain_by_id(brain_id)
        prompt_id = brain.prompt_id if brain else None

        try:
            prompt_id = gr_check(prompt_id, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:5e7b1cc0ff9f3385354b8b91760e8e6cae7fa7a87a1ae429221bdf8894f6a11c')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            prompt_id = prompt_id
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return prompt_id

    def update_brain_by_id(
        self, brain_id: UUID, brain_new_values: BrainUpdatableProperties
    ) -> BrainEntity:
        """Update a prompt by id"""

        existing_brain = self.brain_repository.get_brain_by_id(brain_id)

        if existing_brain is None:
            raise HTTPException(
                status_code=404,
                detail=f"Brain with id {brain_id} not found",
            )

        brain_update_answer = self.brain_repository.update_brain_by_id(
            brain_id,
            brain=BrainUpdatableProperties(
                **brain_new_values.dict(
                    exclude={"brain_definition", "connected_brains_ids"}
                )
            ),
        )

        if brain_update_answer is None:
            raise HTTPException(
                status_code=404,
                detail=f"Brain with id {brain_id} not found",
            )

        if (
            brain_update_answer.brain_type == BrainType.API
            and brain_new_values.brain_definition
        ):
            existing_brain_secrets_definition = (
                existing_brain.brain_definition.secrets
                if existing_brain.brain_definition
                else None
            )
            brain_new_values_secrets_definition = (
                brain_new_values.brain_definition.secrets
                if brain_new_values.brain_definition
                else None
            )
            should_remove_existing_secrets_values = (
                existing_brain_secrets_definition
                and brain_new_values_secrets_definition
                and existing_brain_secrets_definition
                != brain_new_values_secrets_definition
            )

            if should_remove_existing_secrets_values:
                self.delete_brain_secrets_values(brain_id=brain_id)

            api_brain_definition_service.update_api_brain_definition(
                brain_id,
                api_brain_definition=brain_new_values.brain_definition,
            )

        if brain_update_answer is None:
            raise HTTPException(
                status_code=404,
                detail=f"Brain with id {brain_id} not found",
            )

        self.brain_repository.update_brain_last_update_time(brain_id)
        try:
            brain_update_answer = gr_check(brain_update_answer, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:0e419cc6e75de92716c5192f77dddd6b09883fcb3351f90a2b1bb2abcb247a0d')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            brain_update_answer = brain_update_answer
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return brain_update_answer

    def update_brain_last_update_time(self, brain_id: UUID):
        self.brain_repository.update_brain_last_update_time(brain_id)

    def get_brain_details(self, brain_id: UUID) -> BrainEntity | None:
        brain = self.brain_repository.get_brain_details(brain_id)
        if brain == None:
            return None

        if brain.brain_type == BrainType.API:
            brain_definition = api_brain_definition_service.get_api_brain_definition(
                brain_id
            )
            brain.brain_definition = brain_definition

        if brain.brain_type == BrainType.COMPOSITE:
            brain.connected_brains_ids = (
                self.composite_brains_connections_repository.get_connected_brains(
                    brain_id
                )
            )
        try:
            brain = gr_check(brain, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:8fc5ab07f0a07574c0a4c1dedf282000215ae1895091615ef7047fb83b158791')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            brain = brain
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return brain

    def get_connected_brains(self, brain_id: UUID) -> list[BrainEntity]:
        return self.composite_brains_connections_repository.get_connected_brains(
            brain_id
        )

    def get_public_brains(self) -> list[PublicBrain]:
        return self.brain_repository.get_public_brains()

    def update_secret_value(
        self,
        user_id: UUID,
        brain_id: UUID,
        secret_name: str,
        secret_value: str,
    ) -> None:
        """Update an existing secret."""
        self.external_api_secrets_repository.delete_secret(
            user_id=user_id,
            brain_id=brain_id,
            secret_name=secret_name,
        )
        self.external_api_secrets_repository.create_secret(
            user_id=user_id,
            brain_id=brain_id,
            secret_name=secret_name,
            secret_value=secret_value,
        )
