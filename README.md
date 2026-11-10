# SBOM Operator

A Kubernetes operator which generates a [CycloneDX](https://cyclonedx.org) SBOM for container images and stores it in S3.

```console
$ kubectl get sboms
NAME    IMAGE                          PHASE       PACKAGES   AGE
nginx   docker.io/library/nginx:1.29   Completed   152        2m
```

## How it works

1. An `SBOM` object is created which references an image.
2. The operator starts a Pod which mounts the image as a read-only [image volume](https://kubernetes.io/docs/tasks/configure-pod-container/image-volumes/).
3. The scanner discovers packages in the mounted filesystem using [OSV-SCALIBR](https://github.com/google/osv-scalibr)
   (the extraction library which powers [OSV-Scanner](https://github.com/google/osv-scanner)).
4. The SBOM is stored in S3 (CycloneDX 1.6 JSON, gzipped) and the `SBOM` status is updated with the location and package count.

SBOMs are stored at a human readable path:

```
s3://<bucket>/<prefix>/<cluster>/<namespace>/<name>/<sha>.cdx.json.gz
```

`<sha>` is derived from the `SBOM` object's UID. Recreating an `SBOM` writes a new document alongside the previous ones.

Scanner Pods run in the operator namespace using a dedicated ServiceAccount (`sbom-scanner`).
This is the only identity which requires access to the bucket.

## Requirements

* Kubernetes with the `ImageVolume` feature available on the nodes which run scanner Pods (containerd 2.1+ / CRI-O 1.31+).
* Nodes which can pull the images being scanned (image volumes use the same pull credentials as containers).
* An S3 bucket (or S3 compatible storage) and credentials for the `sbom-scanner` ServiceAccount
  eg. [EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html) with `s3:PutObject` on `<bucket>/<prefix>/*`.

## Installation

Update the settings in `config/default/params.env`, then:

```bash
kustomize build config/default | kubectl apply -f -
```

## Usage

```yaml
apiVersion: security.skpr.io/v1beta1
kind: SBOM
metadata:
  name: nginx
spec:
  image: docker.io/library/nginx:1.29
```

## Configuration

All flags can also be set using environment variables, see `sbom-operator --help`.

| Flag | Environment variable | Default | Description |
|---|---|---|---|
| `--cluster` | `SBOM_CLUSTER` | | Name of the cluster, used in the storage path. |
| `--namespace` | `POD_NAMESPACE` | | Namespace where scanner Pods are run. |
| `--scanner-image` | `SBOM_SCANNER_IMAGE` | | Image used by scanner Pods (this image). |
| `--scanner-service-account` | `SBOM_SCANNER_SERVICE_ACCOUNT` | `sbom-scanner` | ServiceAccount used by scanner Pods. |
| `--bucket` | `SBOM_BUCKET` | | Bucket where SBOMs are stored. |
| `--prefix` | `SBOM_PREFIX` | `sbom` | Prefix applied to keys. |
| `--region` | `SBOM_REGION` | | Region where the bucket resides. |
| `--endpoint` | `SBOM_ENDPOINT` | | Endpoint for S3 compatible storage. |
| `--node-selector` | `SBOM_NODE_SELECTOR` | | Node selector for scanner Pods (`key=value`). |
| `--toleration` | `SBOM_TOLERATIONS` | | Tolerations for scanner Pods (`key[=value][:effect]`). |
| `--active-deadline` | `SBOM_ACTIVE_DEADLINE` | `30m` | How long a scanner Pod can run before it fails. |
| `--requests-cpu` / `--requests-memory` | `SBOM_REQUESTS_*` | `100m` / `256Mi` | Scanner Pod requests. |
| `--limits-cpu` / `--limits-memory` | `SBOM_LIMITS_*` | `1` / `1Gi` | Scanner Pod limits. |
| `--skpr-releases` | `SBOM_SKPR_RELEASES` | `false` | Create SBOMs for Skpr Releases. |

## Skpr integration

When `--skpr-releases` is enabled an `SBOM` object is created for each image in a Skpr `Release`
(`workflow.skpr.io/v1beta1`). SBOMs are owned by the Release and are removed with it.

## Notes

* SBOMs are generated once. Delete the `SBOM` object to regenerate it.
* `SBOM` objects use a finalizer to remove their scanner Pod. Keep the operator running until all `SBOM` objects have been deleted.
* The operator never deletes objects from the bucket, so SBOMs outlive their `SBOM` object (and Release) for auditing.
  Retention is controlled by the bucket, eg. a lifecycle rule which expires objects under `<prefix>/`.

## Development

```bash
mise run generate   # Deepcopy, CRDs and RBAC
mise run test
mise run lint
mise run docker
```
