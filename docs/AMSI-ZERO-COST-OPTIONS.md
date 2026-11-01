# AMSI: no-purchase investigation

Checked 1 November 2026. Project constraint: no paid certificates, signing
subscriptions, hardware tokens, or paid trials as a development dependency.

## Findings

The local x64 harness already works without signing or Windows registration.
Purchasing a certificate is not a prerequisite for continuing implementation.

Microsoft documents optional AMSI provider-signature enforcement and describes
`FeatureBits=0x1` as not enforcing that check. A read-only check on this PC found
that value in both 64-bit and 32-bit registry views. No value was changed.
An unsigned provider therefore merits testing under the existing policy in an
ordinary, non-protected AMSI host. This is an inference, not a successful
registration/load test. Other host or application-control policies can matter.
[Microsoft provider documentation](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider)

Protected-process compatibility is separate. Microsoft documents restrictions
on AMSI providers loading into ELAM/PPL-secured processes; a normal code-signing
signature does not establish that compatibility.
[Microsoft developer guidance](https://learn.microsoft.com/en-us/windows/win32/amsi/dev-audience)

## Options

| Option | Cost and practical status |
| --- | --- |
| Current direct-load/native harness | No purchase; already tested. Does not activate Windows-wide AMSI protection. |
| Unsigned provider under an already-permissive policy | Potential no-cost test route. Actual protected installation, service identity, registration/removal and ordinary-host loading remain untested. Do not alter signing enforcement to make it work. |
| Self-created development certificate | Creating one costs nothing, but a signature is not public trust and does not establish acceptance by AMSI/Code Integrity. No certificate or trust-store entry was created. |
| SignPath Foundation | Offers free signing for accepted open-source projects. Requires an eligible OSS license, maintained/released/documented software, verifiable builds, MFA, signing policy, roles and approvals. Acceptance depends on their review. Their policy explicitly permits malware-presence detection, while excluding certain offensive/security-circumvention tools. Our future live-malware lab must be separately reviewed for eligibility. A Foundation signature's acceptance under AMSI-specific policy still requires verification. [Program](https://signpath.org/) · [Terms](https://signpath.org/terms) |
| Azure Artifact Signing | Has paid plans; excluded by this project's no-purchase constraint. [Microsoft pricing information](https://azure.microsoft.com/en-us/products/artifact-signing) |
| Microsoft Store package signing | Package distribution signing does not demonstrate that a separately loaded provider DLL satisfies AMSI's signing policy. It is not an established solution to this problem. [Microsoft MSIX signing guidance](https://learn.microsoft.com/en-us/windows/msix/package/sign-msix-package-guide) |

This checkout has no SentinelAV-root license file or Git metadata. That is not
proof that no public repository exists, but it means we cannot claim SignPath
eligibility from the current local project. No source was published, license
chosen, application submitted, or third party contacted during this research.

## No-purchase development path

1. Continue the byte engine, provider, service and harmless harness work now.
2. Finish protected registration/removal and rollback tooling. Keep it inactive
   until controlled deployment is authorized and a suitable test environment is
   available; VM work remains deferred by the user.
3. During that deployment, record existing signature/application-control policy
   and try ordinary-host loading without weakening it. Record the actual host,
   architecture, provider-load evidence and benign verdict behavior.
4. If the policy rejects the provider, preserve it and report the exact failure.
   Evaluate SignPath only if the owner chooses eligible open-source publication.
   Do not promise that ordinary Authenticode signing satisfies every AMSI policy.
5. If neither route works without purchases or security reductions, retain the
   native harness and existing AMSI consumer feature. Label provider protection
   inactive; do not silently substitute an ineffective integration.

No guaranteed, universally accepted, permanently free AMSI release-signing
route was established. A purchase was also not established as necessary for
this PC's future controlled testing. Kernel-driver signing is a separate issue.
