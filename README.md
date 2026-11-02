# Hardening Kubernetes-Based Open RAN Deployments Against Cyber Threats

Evidence repository for the MSc Cyber Security dissertation, University of Plymouth (2026).

## Structure

- **environment/** — Cluster configuration, node details, tool versions, baseline pod and service state
- **baseline/** — Pre-hardening security assessment results (kube-bench, Trivy, kubeaudit, kube-hunter)
- **hardening/** — All hardening steps with pre-change snapshots and per-workload logs
  - `workload-security/` — SA token mounting, privilege escalation, capabilities, seccomp, non-root, read-only rootfs, AppArmor, privileged-false
  - `network-policies/` — Four NetworkPolicy definitions with dependency validation
  - `rbac/` — AppMgr RBAC scoping from broad cluster-wide permissions to namespace-scoped and resource-specific access
  - `kubelet/` — CIS kubelet configuration hardening
  - `secrets-encryption/` — AES-CBC encryption at rest for Kubernetes Secrets
- **reassessment/** — Post-hardening security assessment results
- **performance-validation/** — Connectivity, connection timing, resource usage, and Prometheus status

## Test Environment

Three-node Minikube v1.38.1 cluster running Kubernetes v1.29.0: 1 control-plane node and 2 worker nodes. OSC Near-RT RIC E-Release deployed via Helm into the `ricplt` namespace.

## Redaction

Kube-hunter internal scan files have been sanitised to remove ServiceAccount JWT material. Sanitised files are suffixed `-sanitised`. The AES-CBC encryption key used for Secrets encryption-at-rest testing is not included in this repository and is additionally excluded by `.gitignore`.

## Tools

| Tool | Version | Purpose |
|------|---------|---------|
| kube-bench | 0.10.6 | CIS Kubernetes Benchmark |
| Trivy | 0.71.0 | Container image CVE scanning |
| kubeaudit | 0.22.2 | Workload security audit |
| kube-hunter | 0.6.8 | Kubernetes penetration testing |

## Author

Babajide Adedeji — MSc Cyber Security, University of Plymouth
