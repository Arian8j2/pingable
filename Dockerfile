FROM alpine:3.22 AS builder
RUN apk update && apk add gcc make linux-headers musl-dev
COPY . .
RUN make clean && make

FROM scratch
COPY --from=builder pingable .
CMD ["./pingable"]
