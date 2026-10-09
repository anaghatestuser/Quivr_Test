import { ChatItem, Notification } from "../types";
// Copyright (c) Lineaje, Inc. All rights reserved.
// Lineaje guardrail helper — inlined once per file (see _import_hint); no npm
// package to install. gr_check() POSTs to GR_SERVICE_URL + "/enforce" and fails
// open (returns `data` unchanged) unless a policy deliberately blocks it
// (GRBlockedError, only on GR_BLOCK_MODE=enforce + an HTTP 403).
type GrEnv = Record<string, string | undefined>;
const _env: GrEnv = ((globalThis as any).process?.env ?? {}) as GrEnv; // Lineaje: env lookup shim (works in Node and browser bundles)

// Lineaje runtime discovery: where this application instance runs, worked out once
// per process and cached (same fields as the Python stub). Environment first, then the
// cloud metadata services (on by default, 200 ms timeouts; UNIFAI_RUNTIME_DISCOVERY_IMDS=0 off).
let _grRuntime: Promise<Record<string, string>> | null = null;

function _grFirstEnv(...names: string[]): string {
  for (const n of names) {
    const v = (_env[n] || "").trim();
    if (v) return v;
  }
  return "";
}

function _grOs(): any {
  const proc: any = (globalThis as any).process;
  try {
    if (proc?.getBuiltinModule) return proc.getBuiltinModule("os");
  } catch { /* not Node */ }
  try {
    const req: any = (globalThis as any).require;
    if (typeof req === "function") return req("os");
  } catch { /* ESM without require */ }
  return null;
}

async function _grGet(url: string, headers: Record<string, string> = {}, method: string = "GET"): Promise<string> {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), 200);
  try {
    const r = await fetch(url, { method, headers, signal: c.signal });
    return r.ok ? (await r.text()).trim() : "";
  } catch {
    return "";
  } finally {
    clearTimeout(t);
  }
}

// Cloud location (same providers as the Python stub and GR): platform env, ECS / Fargate
// task metadata, the link-local metadata service (AWS, Azure, GCP, OCI, DigitalOcean,
// Hetzner, Linode, Vultr, OpenStack) when it answers at all, then Alibaba / Tencent.
function _grSet(f: Record<string, string>, provider: string, region = "", az = "", id = "", name = ""): boolean {
  const pairs: Array<[string, string]> = [["cloud_provider", provider], ["cloud_region", region],
    ["cloud_az", az], ["cloud_instance_id", id], ["cloud_instance_name", name]];
  for (const [k, v] of pairs) if (v && !f[k]) f[k] = String(v);
  return true;
}

async function _grJson(url: string, headers: Record<string, string> = {}): Promise<any> {
  const raw = await _grGet(url, headers);
  try { const d = JSON.parse(raw); return d && typeof d === "object" ? d : null; } catch { return null; }
}

function _grPlatformEnv(f: Record<string, string>): void {
  const e = (...n: string[]) => _grFirstEnv(...n);
  if (e("AWS_LAMBDA_FUNCTION_NAME")) _grSet(f, "aws", e("AWS_REGION", "AWS_DEFAULT_REGION"), "", e("AWS_LAMBDA_LOG_STREAM_NAME"), e("AWS_LAMBDA_FUNCTION_NAME"));
  else if (e("WEBSITE_SITE_NAME")) _grSet(f, "azure", e("REGION_NAME"), "", e("WEBSITE_INSTANCE_ID"), e("WEBSITE_SITE_NAME"));
  else if (e("K_SERVICE")) _grSet(f, "gcp", e("GOOGLE_CLOUD_REGION", "FUNCTION_REGION"), "", "", e("K_REVISION", "K_SERVICE"));
  else if (e("VERCEL_REGION")) _grSet(f, "vercel", e("VERCEL_REGION"), "", e("VERCEL_DEPLOYMENT_ID"), e("VERCEL_URL"));
  else if (e("FLY_REGION")) _grSet(f, "fly", e("FLY_REGION"), "", e("FLY_MACHINE_ID", "FLY_ALLOC_ID"), e("FLY_APP_NAME"));
  else if (e("RAILWAY_REPLICA_ID")) _grSet(f, "railway", e("RAILWAY_REPLICA_REGION"), "", e("RAILWAY_REPLICA_ID"), e("RAILWAY_SERVICE_NAME"));
  else if (e("RENDER_INSTANCE_ID")) _grSet(f, "render", "", "", e("RENDER_INSTANCE_ID"), e("RENDER_SERVICE_NAME"));
  else if (e("DYNO")) _grSet(f, "heroku", "", "", e("DYNO"), e("HEROKU_APP_NAME") || e("DYNO"));
}

async function _grEcs(f: Record<string, string>): Promise<boolean> {
  const base = _grFirstEnv("ECS_CONTAINER_METADATA_URI_V4");
  if (!base) return false;
  const task = await _grJson((base.endsWith("/") ? base.slice(0, -1) : base) + "/task");
  if (!task) return false;
  const arn = String(task.TaskARN || "");
  const parts = arn.split(":");
  const family = [task.Family, task.Revision].filter((x: any) => x !== undefined && x !== "").join(":");
  _grSet(f, "aws", parts.length > 3 ? parts[3] : "", String(task.AvailabilityZone || ""), arn.split("/").pop() || "", family);
  const cluster = String(task.Cluster || "");
  if (cluster && !f.cluster) f.cluster = cluster.split("/").pop() || "";
  return true;
}

async function _grReachable(host: string): Promise<boolean> {
  // Any HTTP answer (even 404) means a metadata service is there.
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), 200);
  try { await fetch("http://" + host + "/", { signal: c.signal }); return true; }
  catch { return false; }
  finally { clearTimeout(t); }
}

const _GR_LL = "http://169.254.169.254";

async function _grAws(f: Record<string, string>): Promise<boolean> {
  const token = await _grGet(_GR_LL + "/latest/api/token", { "X-aws-ec2-metadata-token-ttl-seconds": "60" }, "PUT");
  if (!token) return false;
  const h = { "X-aws-ec2-metadata-token": token };
  const b = _GR_LL + "/latest/meta-data/";
  const name = (await _grGet(b + "tags/instance/Name", h)) || (await _grGet(b + "local-hostname", h));
  return _grSet(f, "aws", await _grGet(b + "placement/region", h), await _grGet(b + "placement/availability-zone", h), await _grGet(b + "instance-id", h), name);
}

async function _grAzure(f: Record<string, string>): Promise<boolean> {
  const c = await _grJson(_GR_LL + "/metadata/instance/compute?api-version=2021-02-01", { Metadata: "true" });
  if (!c) return false;
  return _grSet(f, "azure", String(c.location || ""), String(c.zone || ""), String(c.vmId || ""), String(c.name || ""));
}

async function _grGcp(f: Record<string, string>): Promise<boolean> {
  const h = { "Metadata-Flavor": "Google" };
  const b = "http://metadata.google.internal/computeMetadata/v1/instance/";
  const id = await _grGet(b + "id", h);
  if (!id) return false;
  const zone = (await _grGet(b + "zone", h)).split("/").pop() || "";
  const region = (await _grGet(b + "region", h)).split("/").pop() || zone.split("-").slice(0, -1).join("-");
  return _grSet(f, "gcp", region, zone, id, await _grGet(b + "name", h));
}

async function _grOci(f: Record<string, string>): Promise<boolean> {
  const i = await _grJson(_GR_LL + "/opc/v2/instance/", { Authorization: "Bearer Oracle" });
  if (!i) return false;
  return _grSet(f, "oci", String(i.canonicalRegionName || i.region || ""), String(i.availabilityDomain || ""), String(i.id || ""), String(i.displayName || ""));
}

async function _grDigitalOcean(f: Record<string, string>): Promise<boolean> {
  const m = await _grJson(_GR_LL + "/metadata/v1.json");
  if (!m || m.droplet_id === undefined) return false;
  return _grSet(f, "digitalocean", String(m.region || ""), "", String(m.droplet_id || ""), String(m.hostname || ""));
}

async function _grHetzner(f: Record<string, string>): Promise<boolean> {
  const b = _GR_LL + "/hetzner/v1/metadata/";
  const id = await _grGet(b + "instance-id");
  if (!id || !/^[0-9]+$/.test(id)) return false;
  return _grSet(f, "hetzner", await _grGet(b + "region"), await _grGet(b + "availability-zone"), id, await _grGet(b + "hostname"));
}

async function _grLinode(f: Record<string, string>): Promise<boolean> {
  const token = await _grGet(_GR_LL + "/v1/token", { "Metadata-Token-Expiry-Seconds": "60" }, "PUT");
  if (!token) return false;
  const i = await _grJson(_GR_LL + "/v1/instance", { "Metadata-Token": token, Accept: "application/json" });
  if (!i) return false;
  return _grSet(f, "linode", String(i.region || ""), "", String(i.id || ""), String(i.label || ""));
}

async function _grVultr(f: Record<string, string>): Promise<boolean> {
  const m = await _grJson(_GR_LL + "/v1.json");
  if (!m || m.instanceid === undefined) return false;
  const region = m.region && typeof m.region === "object" ? m.region.regioncode : m.region;
  return _grSet(f, "vultr", String(region || ""), "", String(m.instanceid || ""), String(m.hostname || ""));
}

async function _grOpenStack(f: Record<string, string>): Promise<boolean> {
  const m = await _grJson(_GR_LL + "/openstack/latest/meta_data.json");
  if (!m || m.uuid === undefined) return false;
  return _grSet(f, "openstack", "", String(m.availability_zone || ""), String(m.uuid || ""), String(m.name || m.hostname || ""));
}

async function _grAlibaba(f: Record<string, string>): Promise<boolean> {
  const b = "http://100.100.100.200/latest/meta-data/";
  const id = await _grGet(b + "instance-id");
  if (!id) return false;
  return _grSet(f, "alibaba", await _grGet(b + "region-id"), await _grGet(b + "zone-id"), id, (await _grGet(b + "instance/instance-name")) || (await _grGet(b + "hostname")));
}

async function _grTencent(f: Record<string, string>): Promise<boolean> {
  const b = "http://metadata.tencentyun.com/latest/meta-data/";
  const id = await _grGet(b + "instance-id");
  if (!id) return false;
  return _grSet(f, "tencent", await _grGet(b + "placement/region"), await _grGet(b + "placement/zone"), id, await _grGet(b + "instance-name"));
}

async function _grImds(f: Record<string, string>): Promise<void> {
  _grPlatformEnv(f);
  if (f.cloud_provider && f.cloud_region && f.cloud_az && f.cloud_instance_id && f.cloud_instance_name) return;
  if (await _grEcs(f)) return;
  if (await _grReachable("169.254.169.254")) {
    for (const probe of [_grAws, _grAzure, _grGcp, _grOci, _grDigitalOcean, _grHetzner, _grLinode, _grVultr, _grOpenStack]) {
      if (await probe(f)) return;
    }
  }
  if (!f.cloud_provider) {
    if (await _grReachable("100.100.100.200") && await _grAlibaba(f)) return;
    await _grTencent(f);
  }
}

// Lineaje identity for the runtime JSONs: tenant_id, company_id, org_name from the
// token's claims (and user_metadata), else GR_TENANT_ID / GR_COMPANY_ID / LINEAJE_ORG_NAME.
// Resolved at runtime; never written into the call sites.
function _grIdentity(bearer: string): Record<string, string> {
  let claims: any = {};
  try {
    const part = (bearer || "").split(".")[1];
    if (part) {
      const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
      const g: any = globalThis as any;
      const text = g.Buffer ? g.Buffer.from(b64, "base64").toString("utf8") : g.atob(b64);
      claims = JSON.parse(text) || {};
    }
  } catch { claims = {}; }
  const meta: any = (claims && typeof claims.user_metadata === "object" && claims.user_metadata) || {};
  const pick = (keys: string[], envs: string[]): string => {
    for (const k of keys) {
      for (const src of [claims, meta]) {
        const v = src?.[k];
        if (typeof v === "string" && v.trim()) return v.trim();
      }
    }
    return _grFirstEnv(...envs);
  };
  return {
    tenant_id: pick(["tenant_id", "tenantId"], ["GR_TENANT_ID", "LINEAJE_TENANT_ID"]),
    company_id: pick(["company_id", "companyId"], ["GR_COMPANY_ID", "LINEAJE_COMPANY_ID"]),
    org_name: pick(["active_org_name", "org_name", "org"], ["LINEAJE_ORG_NAME", "GR_ORG_NAME"]),
  };
}

// Lineaje heartbeat: one per application process (not per call site), on a timer,
// to GR's POST /heartbeat (GR_HEARTBEAT_URL overrides the endpoint). UNIFAI_HEARTBEAT_SECS
// sets the interval (default 1800, every 30 minutes); UNIFAI_HEARTBEAT=0 turns it off.
// Never keeps the process alive (unref).
let _grHeartbeatStarted = false;

function _grStartHeartbeat(base: string, bearer: string, body: Record<string, unknown>): void {
  if (_grHeartbeatStarted) return;
  if (["0", "false", "no", "off"].includes(_grFirstEnv("UNIFAI_HEARTBEAT").toLowerCase())) return;
  _grHeartbeatStarted = true;
  const secs = Math.max(30, parseInt(_grFirstEnv("UNIFAI_HEARTBEAT_SECS") || "1800", 10) || 1800);
  const target = _grFirstEnv("GR_HEARTBEAT_URL").replace(/[/]+$/, "") || base + "/heartbeat";
  const beat = async (): Promise<void> => {
    try {
      await fetch(target, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + bearer },
        body: JSON.stringify({ ...body, interval_secs: secs }),
      });
    } catch { /* a missed beat is what marks an instance stale */ }
  };
  void beat();
  const timer: any = setInterval(() => { void beat(); }, secs * 1000);
  if (timer && typeof timer.unref === "function") timer.unref();
}

export function grRuntimeDiscovery(): Promise<Record<string, string>> {
  if (_grRuntime) return _grRuntime;
  _grRuntime = (async () => {
    const found: Record<string, string> = {};
    try {
      let provider = _grFirstEnv("UNIFAI_CLOUD_PROVIDER", "GR_CLOUD_PROVIDER");
      if (!provider) {
        if (_grFirstEnv("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_EXECUTION_ENV", "ECS_CONTAINER_METADATA_URI_V4")) provider = "aws";
        else if (_grFirstEnv("WEBSITE_SITE_NAME", "AZURE_REGION", "REGION_NAME", "IDENTITY_ENDPOINT")) provider = "azure";
        else if (_grFirstEnv("GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "K_SERVICE", "FUNCTION_REGION")) provider = "gcp";
      }
      if (provider) found.cloud_provider = provider.toLowerCase();
      const region = _grFirstEnv("UNIFAI_CLOUD_REGION", "GR_REGION", "AWS_REGION", "AWS_DEFAULT_REGION", "AZURE_REGION", "REGION_NAME", "GOOGLE_CLOUD_REGION", "GCP_REGION", "FUNCTION_REGION");
      if (region) found.cloud_region = region;
      const zone = _grFirstEnv("UNIFAI_CLOUD_AZ", "GR_AZ", "AWS_AVAILABILITY_ZONE", "AZURE_ZONE", "GCP_ZONE");
      if (zone) found.cloud_az = zone;
      const inst = _grFirstEnv("UNIFAI_CLOUD_INSTANCE_ID", "GR_INSTANCE_ID", "EC2_INSTANCE_ID", "WEBSITE_INSTANCE_ID");
      if (inst) found.cloud_instance_id = inst;
      // Cloud metadata (AWS / Azure / GCP): on by default, off with UNIFAI_RUNTIME_DISCOVERY_IMDS=0.
      if (!["0", "false", "no", "off"].includes(_grFirstEnv("UNIFAI_RUNTIME_DISCOVERY_IMDS").toLowerCase())) {
        await _grImds(found);
      }
      const os = _grOs();
      found.hostname = _grFirstEnv("HOSTNAME") || (os?.hostname ? os.hostname() : "");
      found.cloud_instance_name = _grFirstEnv("UNIFAI_CLOUD_INSTANCE_NAME") || found.cloud_instance_name || found.hostname;
      let ip = _grFirstEnv("UNIFAI_APP_IP", "POD_IP");
      if (!ip && os?.networkInterfaces) {
        for (const addrs of Object.values(os.networkInterfaces() as Record<string, any[]>)) {
          const hit = (addrs || []).find((a: any) => a && !a.internal && (a.family === "IPv4" || a.family === 4));
          if (hit) { ip = hit.address; break; }
        }
      }
      if (ip) found.ip = ip;
      const extra: Array<[string, string[]]> = [
        ["source_code_name", ["UNIFAI_APP_NAME", "GR_APP_NAME"]],
        ["source_code_version", ["UNIFAI_APP_VERSION", "GR_APP_VERSION"]],
        ["source_code_branch", ["UNIFAI_APP_BRANCH", "GR_APP_BRANCH"]],
        ["cluster", ["UNIFAI_CLUSTER", "GR_CLUSTER"]],
        ["pod_name", ["POD_NAME"]],
        ["namespace", ["POD_NAMESPACE"]],
        ["node_name", ["NODE_NAME"]],
      ];
      for (const [key, names] of extra) {
        const v = _grFirstEnv(...names);
        if (v) found[key] = v;
      }
    } catch { /* never break the call path over discovery */ }
    return Object.fromEntries(Object.entries(found).filter(([, v]) => !!v));
  })();
  return _grRuntime;
}

export class GRBlockedError extends Error {
  policyId: string;
  reason: string;

  constructor(policyId: string, reason: string) {
    super(`Guardrail block for policy '${policyId}': ${reason}`);
    this.name = "GRBlockedError";
    this.policyId = policyId;
    this.reason = reason;
  }
}

export async function gr_check(
  data: unknown,
  sourceType: string,
  destinationType: string,
  tenantId: string = "",
  timeoutMs: number = 5000,
  // string[] is required here (not just string | undefined): candidate_policies
  // is always passed as a JSON array literal (see _policy_id_json_array's call
  // site) — a real incident had every generated call site fail strict
  // TypeScript compilation with "Type 'string[]' is not assignable to type
  // 'string'" because this signature only allowed scalar string values.
  // components (an object: the site's build-time identity and call site) is sent
  // as-is, like site_id and candidate_policies.
  context: Record<string, unknown> = {},
): Promise<unknown> {
  const url = _env["GR_SERVICE_URL"] || "";
  if (!url) {
    return data; // fail-open: GR_SERVICE_URL not configured
  }

  const tid = tenantId || _env["GR_TENANT_ID"] || "";
  const bearer = _env["GR_BEARER_TOKEN"] || _env["LINEAJE_REFRESH_TOKEN"] || _env["LINEAJE_PAT_TOKEN"] || _env["LINEAJE_PAT"] || "";
  const hopLabel = `${sourceType}->${destinationType}`;
  const paramsKey = destinationType === "agent" ? "out_params" : "in_params";

  const body: Record<string, unknown> = {
    source_type: sourceType,
    destination_type: destinationType,
    [paramsKey]: { data },
  };
  for (const [k, v] of Object.entries(context)) {
    if (v) {
      body[k] = v;
    }
  }
  if (tid) {
    body["tenant_id"] = tid;
  }
  const grIdentity = _grIdentity(bearer);
  if (!body["tenant_id"] && grIdentity.tenant_id) body["tenant_id"] = grIdentity.tenant_id;
  if (!body["company_id"] && grIdentity.company_id) body["company_id"] = grIdentity.company_id;
  if (!body["org_name"] && grIdentity.org_name) body["org_name"] = grIdentity.org_name;
  // Cached once per process: where this application instance runs.
  const runtimeContext = await grRuntimeDiscovery();
  body["runtime_context"] = runtimeContext;
  if (!body["app_ip"] && runtimeContext.ip) {
    body["app_ip"] = runtimeContext.ip;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let base = url.replace(/\/+$/, "");
  if (/\/enforce$/i.test(base)) {
    base = base.slice(0, -"/enforce".length); // Lineaje: GR_SERVICE_URL may already carry /enforce
  }

  _grStartHeartbeat(base, bearer, {
    tenant_id: body["tenant_id"] || tid,
    company_id: body["company_id"] || "",
    org_name: body["org_name"] || "",
    project_name: runtimeContext.source_code_name || body["project_name"] || "",
    project_version: runtimeContext.source_code_version || body["project_version"] || "",
    project_branch: runtimeContext.source_code_branch || body["project_branch"] || "",
    app_ip: body["app_ip"] || "",
    runtime_context: runtimeContext,
  });

  let resp: Response;
  try {
    resp = await fetch(base + "/enforce", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + bearer,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (exc) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (${exc}) — failing open`,
    );
    return data;
  } finally {
    clearTimeout(timer);
  }

  if (resp.status === 403) {
    let detail: any = {};
    try {
      const errBody: any = await resp.json();
      detail = errBody?.detail ?? {};
    } catch {
      detail = {};
    }
    const blockedBy = detail.blocked_by ?? [];
    const policyId = blockedBy[0]?.policy_id ?? "unknown";
    const reason = detail.message ?? "Request denied by policy enforcement.";
    console.warn(
      `gr_client[${hopLabel}]: BLOCKED by policy=${policyId} — ${reason}`,
    );
    if ((_env["GR_BLOCK_MODE"] || "enforce").toLowerCase() === "audit") {
      return data;
    }
    throw new GRBlockedError(policyId, reason);
  }

  if (!resp.ok) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (HTTP ${resp.status}) — failing open`,
    );
    return data;
  }

  let result: any;
  try {
    result = await resp.json();
  } catch (exc) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (${exc}) — failing open`,
    );
    return data;
  }

  if (result?.status === "escalate") {
    console.warn(
      `gr_client[${hopLabel}]: escalation flagged — passing through for human review`,
    );
  }

  return result?.result?.data ?? data;
}

export const getNotificationsFromChatItems = (
  chatItems: ChatItem[]
): Notification[] => {
  const messages = chatItems
    .filter((item) => item.item_type === "NOTIFICATION")
    .map((item) => item.body as Notification);

  void gr_check(messages, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_VULN_SEC_005"] }).catch((_grExc) => {
    if (_grExc instanceof GRBlockedError) {
      console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
    }
  }); // fire-and-forget (sync context)
  return messages;
};
