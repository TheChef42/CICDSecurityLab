FROM alpine:latest

RUN echo "mutable base image tag example" \
    && addgroup -S appgroup && adduser -S appuser -G appgroup

USER appuser

HEALTHCHECK --interval=30s --timeout=5s CMD echo ok || exit 1
