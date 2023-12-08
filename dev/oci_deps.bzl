"""
Load external dependencies for base images
"""

load("@rules_oci//oci:pull.bzl", "oci_pull")

# Quick script to get the latest tags for each of the base images from GCR:
#
# grep 'image = ' ./dev/oci_deps.bzl | while read -r str ; do
#   str_no_spaces="${str#"${str%%[![:space:]]*}"}"  # remove leading spaces
#   url="${str_no_spaces#*\"}"  # remove prefix until first quote
#   url="${url%%\"*}"  # remove suffix from first quote
#
#   IMAGE_DETAILS=$(gcloud container images list-tags $url --limit=1 --sort-by=~timestamp --format=json)
#   TAG=$(echo $IMAGE_DETAILS | jq -r '.[0].tags[0]')
#   DIGEST=$(echo $IMAGE_DETAILS | jq -r '.[0].digest')
#
#   echo $url
#   echo $DIGEST
# done
#
#
# Quick script to get the latest tags for each of the base images from Dockerhub:
# grep 'image = ' ./dev/oci_deps.bzl | while read -r str ; do
#   str_no_spaces="${str#"${str%%[![:space:]]*}"}"  # remove leading spaces
#   url="${str_no_spaces#*\"}"  # remove prefix until first quote
#   url="${url%%\"*}"  # remove suffix from first quote

#     TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${url}:pull" | jq -r .token)

#   DIGEST=$(curl -I -s -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
#     https://registry-1.docker.io/v2/${url}/manifests/latest \
#     | grep -i Docker-Content-Digest | awk '{print $2}')

#   echo -e "$url\n$DIGEST\n\n"
# done

def oci_deps():
    """
    The image definitions and their digests
    """
    oci_pull(
        name = "wolfi_base",
        digest = "sha256:c5b3e87d59bde34722dc969d0eef8b9740771c521fc5de8c7dbc849de3319d7f",
        image = "index.docker.io/sourcegraph/wolfi-sourcegraph-base",
    )

    oci_pull(
        name = "wolfi_cadvisor_base",
        digest = "sha256:be99d2faeab8a11b56aca9c1ceae41cde0130c2015a7635afc04e2a574472f5b",
        image = "index.docker.io/sourcegraph/wolfi-cadvisor-base",
    )

    oci_pull(
        name = "wolfi_symbols_base",
        digest = "sha256:6ec382c9266486cf9a28fd06c93ca854ec9324c7f400923c362894cc98433af0",
        image = "index.docker.io/sourcegraph/wolfi-symbols-base",
    )

    oci_pull(
        name = "wolfi_server_base",
        digest = "sha256:bef9950463f80d4d908a527e6949434ef3febbf9e9a1cdd21fca736117f9867e",
        image = "index.docker.io/sourcegraph/wolfi-server-base",
    )

    oci_pull(
        name = "wolfi_gitserver_base",
        digest = "sha256:7d336e9326312125b8d01a89198f24aebbfc8c96b4ddf821ae9706967096f597",
        image = "index.docker.io/sourcegraph/wolfi-gitserver-base",
    )

    oci_pull(
        name = "wolfi_grafana_base",
        digest = "sha256:461ef0c0233c20716398a0ad1a38dc2df955e26ec091400f64a18fa7de9d2621",
        image = "us.gcr.io/sourcegraph-dev/wolfi-grafana",
    )

    oci_pull(
        name = "wolfi_postgres_exporter_base",
        digest = "sha256:fcaf4d510d6e39107ed403574e1bb1414ab94f93c5b22ddc9a1c3092045384e5",
        image = "index.docker.io/sourcegraph/wolfi-postgres-exporter-base",
    )

    oci_pull(
        name = "wolfi_jaeger_all_in_one_base",
        digest = "sha256:74b66ad7db2ef501cff4a32f4ce0ef587cad8b9b26024ea3cc9e40cdd118193e",
        image = "index.docker.io/sourcegraph/wolfi-jaeger-all-in-one-base",
    )

    oci_pull(
        name = "wolfi_jaeger_agent_base",
        digest = "sha256:972ce0619f2fa14d5d45a3cfd1d3075e82eea7840b078c6add757ad40ed53834",
        image = "index.docker.io/sourcegraph/wolfi-jaeger-agent-base",
    )

    oci_pull(
        name = "wolfi_redis_base",
        digest = "sha256:f64d75031cc1ba1751974841032e804ed627b9f13403f0cad617f59f45a72fcb",
        image = "index.docker.io/sourcegraph/wolfi-redis-base",
    )

    oci_pull(
        name = "wolfi_redis_exporter_base",
        digest = "sha256:b822f375712ca35551e077790535595c4823a78770d99faa1bff12e49299bef5",
        image = "index.docker.io/sourcegraph/wolfi-redis-exporter-base",
    )

    oci_pull(
        name = "wolfi_syntax_highlighter_base",
        digest = "sha256:8ef988b73900a730d52f9db1a7755e4b95b1d78edf8326a12e0a77ab7f98f8eb",
        image = "index.docker.io/sourcegraph/wolfi-syntax-highlighter-base",
    )

    oci_pull(
        name = "wolfi_search_indexer_base",
        digest = "sha256:e179c5458859f0102645689ee4dae01a4e693346e1befd06c9c84d5d30b217d9",
        image = "index.docker.io/sourcegraph/wolfi-search-indexer-base",
    )

    oci_pull(
        name = "wolfi_repo_updater_base",
        digest = "sha256:017e2629c0d60d29e034feb52eccd3d564004cd97eb57a89cb5738bd89ebc978",
        image = "index.docker.io/sourcegraph/wolfi-repo-updater-base",
    )

    oci_pull(
        name = "wolfi_searcher_base",
        digest = "sha256:48b2539708efda5ad4cdb7602459c423fde17c1e4fd509505606b9147b4abb5a",
        image = "index.docker.io/sourcegraph/wolfi-searcher-base",
    )

    oci_pull(
        name = "wolfi_executor_base",
        digest = "sha256:a2f55d5cda032a42e78df2e15310a94dcf0b9fd082f363c4e38ffe08ffca7692",
        image = "index.docker.io/sourcegraph/wolfi-executor-base",
    )

    # ???
    oci_pull(
        name = "wolfi_bundled_executor_base",
        digest = "sha256:b480ea78e6208b1eb065f531d391c7dfd224c5a072dce81488b0ae490f81ad51",
        image = "index.docker.io/sourcegraph/wolfi-bundled-executor-base",
    )

    oci_pull(
        name = "wolfi_executor_kubernetes_base",
        digest = "sha256:1f67a4df973ddeade0176900c655d10303786dbfd27fab66a0df8a889b1356dd",
        image = "index.docker.io/sourcegraph/wolfi-executor-kubernetes-base",
    )

    oci_pull(
        name = "wolfi_batcheshelper_base",
        digest = "sha256:8d69b1bd65b4f6a3207fd58d223503f340ad6fd1aa7b5bb9ebf2510c8c1117eb",
        image = "index.docker.io/sourcegraph/wolfi-batcheshelper-base",
    )

    oci_pull(
        name = "wolfi_prometheus_base",
        digest = "sha256:0b84ad480845dd06a2d5859acaef1e0c8bb7ea463506e2659a61f9c2081016d0",
        image = "index.docker.io/sourcegraph/wolfi-prometheus-base",
    )

    oci_pull(
        name = "wolfi_prometheus_gcp_base",
        digest = "sha256:4ced2089cd368aeaa45a3066932247396809e6c736221620645f22a8de93774a",
        image = "index.docker.io/sourcegraph/wolfi-prometheus-gcp-base",
    )

    oci_pull(
        name = "wolfi_postgresql-12_base",
        digest = "sha256:7d1e1099100785553ac9ec3a23b9cd0669be1ad4cf59a2e06989c0eb9f3aa84c",
        image = "index.docker.io/sourcegraph/wolfi-postgresql-12-base",
    )

    oci_pull(
        name = "wolfi_postgresql-12-codeinsights_base",
        digest = "sha256:9be14d0b97ba76378f9f3faad9b089b89b4b517d82b576bba099fadf45ea350c",
        image = "index.docker.io/sourcegraph/wolfi-postgresql-12-codeinsights-base",
    )

    oci_pull(
        name = "wolfi_node_exporter_base",
        digest = "sha256:e94ef74e3cf44327a838a7394664120a766140b81187ce30bb887f198b8a1da8",
        image = "index.docker.io/sourcegraph/wolfi-node-exporter-base",
    )

    oci_pull(
        name = "wolfi_opentelemetry_collector_base",
        digest = "sha256:60263642dd9c31f73af01032caa274d4c58de6c43d622af6c27da7127055fabe",
        image = "index.docker.io/sourcegraph/wolfi-opentelemetry-collector-base",
    )

    oci_pull(
        name = "wolfi_searcher_base",
        digest = "sha256:48b2539708efda5ad4cdb7602459c423fde17c1e4fd509505606b9147b4abb5a",
        image = "index.docker.io/sourcegraph/wolfi-searcher-base",
    )

    oci_pull(
        name = "wolfi_s3proxy_base",
        digest = "sha256:f9662a738ecd33b92dd63b1fa64f43bf8e3e72594417b12446965482987c2c41",
        image = "index.docker.io/sourcegraph/wolfi-blobstore-base",
    )

    oci_pull(
        name = "wolfi_qdrant_base",
        digest = "sha256:e5dcde823b7f897d56f90030d167780deb75b2e34e98c64e2e8371cd612d306c",
        image = "index.docker.io/sourcegraph/wolfi-qdrant-base",
    )

    # The following image digests are from tag 252535_2023-11-28_5.2-82b5f4f5d73f. sg wolfi update-hashes DOES NOT update these digests.
    # To rebuild these legacy images using docker and outside of bazel you can either push a branch to:
    # - docker-images-candidates-notest/<your banch name here>
    # or you can run `sg ci build docker-images-candidates-notest`
    oci_pull(
        name = "legacy_alpine-3.14_base",
        digest = "sha256:581afabd476b4918b14295ae6dd184f4a3783c64bab8bde9ad7b11ea984498a8",
        image = "index.docker.io/sourcegraph/alpine-3.14",
    )

    oci_pull(
        name = "legacy_dind_base",
        digest = "sha256:0893c2e6103cde39b609efea0ebd6423c7af8dafdf19d613debbc12b05fefd54",
        image = "index.docker.io/sourcegraph/dind",
    )

    oci_pull(
        name = "legacy_executor-vm_base",
        digest = "sha256:4b23a8bbfa9e1f5c80b167e59c7f0d07e40b4af52494c22da088a1c97925a3e2",
        image = "index.docker.io/sourcegraph/executor-vm",
    )

    oci_pull(
        name = "legacy_codeinsights-db_base",
        digest = "sha256:c2384743265457f816d83358d8fb4810b9aac9f049fd462d1f630174076e0d94",
        image = "index.docker.io/sourcegraph/codeinsights-db",
    )

    oci_pull(
        name = "legacy_codeintel-db_base",
        digest = "sha256:dcc32a6d845356288186f2ced62346cf7e0120977ff1a0d6758f4e11120401f7",
        image = "index.docker.io/sourcegraph/codeintel-db",
    )

    oci_pull(
        name = "legacy_postgres-12-alpine_base",
        digest = "sha256:dcc32a6d845356288186f2ced62346cf7e0120977ff1a0d6758f4e11120401f7",
        image = "index.docker.io/sourcegraph/postgres-12-alpine",
    )
