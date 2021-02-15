all: net_action

net_action: net_action.p4
	p4c-bm2-ss --std p4-16 \
		--target bmv2 --arch v1model \
		-o net_action.json \
		--p4runtime-file net_action.p4info \
		--p4runtime-format text net_action.p4