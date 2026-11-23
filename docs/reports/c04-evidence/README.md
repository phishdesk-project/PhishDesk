# C04 recovered screenshot evidence

Reviewed November 1, 2026. These are privacy-reviewed, unmodified copies of available original evidence, with SHA-256 and provenance in [manifest.json](manifest.json). Chat uploads came from `phishdesk`; prior Desktop captures are explicitly historical. Duplicate cached copies were deduplicated. No screenshots were generated or reconstructed. Account-identifying screenshots are inventoried by digest but excluded; no credential files were collected.

| Capture | What it supports |
| --- | --- |
| [fixture-mount.png](fixture-mount.png) | Read-only iso9660 fixture disc and no HGFS mounts; not a network test. |
| [manual-render.png](manual-render.png) | Firefox owned file rendering with synthetic marker; not proof of containment or fixture byte identity. |
| [route-lookups.png](route-lookups.png) | Three IPv4 and one IPv6 route lookups unreachable; read-only fixture mount. Route lookups do not send probes. |
| [headless-timeout.png](headless-timeout.png) | file reports PNG 1280x720; 10-second screenshot exit 0; timeout of sleep 15 exits 124. |
| [file-quota.png](file-quota.png) | Synthetic dd quota attempt exits 153, 16384 bytes, then removal command. Firefox quota was not tested. |
| [historical-boot.png](historical-boot.png) | Earlier Ubuntu boot framebuffer only, 1280x800; not the synthetic page. |
| [historical-console-blocker.png](historical-console-blocker.png) | Earlier failed console automation record; does not verify policy installation. |
| [historical-pr.jpg](historical-pr.jpg) | Outdated original PR state; retained only as history. |
| [historical-blockers.jpg](historical-blockers.jpg) | Outdated unavailable-resource issue state; retained only as history. |

The policy-active screen and five explicit denial captures could not be recovered. Those results are accepted as the user's verified manual observations, separately attributed in [the test record](../c04-final-tests.json); they are not presented as visually reverified screenshots. The recovered terminal screenshot reports 1280x720 PNG files, but the original headless PNG files themselves were not recovered. The manual-render image is a separate GUI screenshot.

No non-loopback interfaces or routes and the tested policy denials support an offline feasibility result. They do not establish independently measured zero boundary traffic, browser-wide failure cleanup, or full production containment. Historical blocker images do not represent current acceptance status. Original source files were not modified.
