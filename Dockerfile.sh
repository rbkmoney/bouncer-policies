#!/bin/bash
cat <<EOF

# openpolicyagent/opa:0.24.0
FROM openpolicyagent/opa@sha256:dd8233c85e13ca42b057962faf5579732c8b2874e469fbb19cea3f11f7372fd9
COPY ./policies /var/opa/roots
WORKDIR /var/opa/roots

CMD [ "run", \
        "--server", \
        "--addr", ":8181", \
        "--bundle", ".", \
        "--authorization", "basic" \
    ]

EXPOSE 8181

LABEL \
    maintainer="Andrey Mayorov <a.mayorov@rbkmoney.com>" \
    com.rbkmoney.$SERVICE_NAME.parent=$BASE_IMAGE_NAME \
    com.rbkmoney.$SERVICE_NAME.parent_tag=$BASE_IMAGE_TAG \
    com.rbkmoney.$SERVICE_NAME.commit_id=$(git rev-parse HEAD) \
    com.rbkmoney.$SERVICE_NAME.commit_number=$(git rev-list --count HEAD) \
    com.rbkmoney.$SERVICE_NAME.branch=$( \
    if [ "HEAD" != $(git rev-parse --abbrev-ref HEAD) ]; then \
    echo $(git rev-parse --abbrev-ref HEAD); \
    elif [ -n "$BRANCH_NAME" ]; then \
    echo $BRANCH_NAME; \
    else \
    echo $(git name-rev --name-only HEAD); \
    fi)

EOF
