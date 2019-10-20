IMAGE_NAME := "zachomedia/cert-manager-webhook-ibm-cis"
IMAGE_TAG := "latest"

OUT := $(shell pwd)/_out

$(shell mkdir -p "$(OUT)")

verify:
	go test -v .

build:
	docker build -t "$(IMAGE_NAME):$(IMAGE_TAG)" .

.PHONY: rendered-manifest.yaml
rendered-manifest.yaml:
	helm template \
	    --name cert-manager-webhook-ibm-cis \
        --set image.repository=$(IMAGE_NAME) \
        --set image.tag=$(IMAGE_TAG) \
        deploy/cert-manager-webhook-ibm-cis > "$(OUT)/rendered-manifest.yaml"
