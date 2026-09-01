# syntax=docker/dockerfile:1

# SAMPLE Dockerfile this builds the binary, then copies it over to a
# minimal Docker image to save size. 
# When building an image for Kubernetes, comment out the COPY commands
# that copy out the mappings.json and basicauth-config.yaml files and 
# use K8s configmap or similar to allow for more flexibility.

FROM golang:1.26-alpine AS builder

WORKDIR /github.com/usnisgov/basicauth

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum .
RUN go mod download && go mod verify

COPY main.go .
COPY authsrv ./authsrv

RUN CGO_ENABLED=0 go build -o basicauth .

#now put it into a smaller comtainer with just the binary
FROM alpine:latest 

COPY --from=builder /github.com/usnisgov/basicauth /

#stuff needed for the image
COPY mappings.json /
COPY basicauth-config.yaml /

EXPOSE 8800
CMD ["/basicauth"]
