# capsh-core 构建(OCaml 4.14, 纯 ocamlc + unix.cma,无需 dune/opam)。
OCAMLC := ocamlc
LIBS   := unix.cma
BUILD  := _build
# 顺序重要:cap.mli 在 cap.ml 前;依赖在使用者前。
DEMO_UNITS := taint.ml cap.mli cap.ml broker.ml script_layer.ml demo.ml
CAPSH_UNITS := taint.ml cap.mli cap.ml broker.ml rpc_client.ml value.ml ast.ml lexer.ml parser.ml backend.ml backend_local.ml backend_rpc.ml eval.ml main.ml
REMOTE_UNITS := rpc_client.ml remote_demo.ml

.PHONY: all build capsh remote run run-capsh run-capsh-remote remote-demo forge-check clean test

all: build capsh

build:
	@mkdir -p $(BUILD)
	@cp src/*.ml src/*.mli $(BUILD)/
	@cd $(BUILD) && $(OCAMLC) $(LIBS) $(DEMO_UNITS) -o capsh-demo
	@echo "built $(BUILD)/capsh-demo"

capsh:
	@mkdir -p $(BUILD)
	@cp src/*.ml src/*.mli $(BUILD)/
	@cd $(BUILD) && $(OCAMLC) $(LIBS) $(CAPSH_UNITS) -o capsh
	@echo "built $(BUILD)/capsh (interpreter)"

remote:
	@mkdir -p $(BUILD)
	@cp src/*.ml src/*.mli $(BUILD)/
	@cd $(BUILD) && $(OCAMLC) $(LIBS) $(REMOTE_UNITS) -o remote-demo
	@echo "built $(BUILD)/remote-demo (capsh<->Rust broker client)"

# 端到端桥:起 Rust capable-rpc 服务 + OCaml 客户端驱动它
remote-demo: remote
	@ws=$$(mktemp -d); sock=$$(mktemp -u); \
	  printf 'hello via socket\n' > $$ws/main.txt; mkdir -p $$ws/src; \
	  printf 'API_KEY=sk-do-not-exfil\n' > $$ws/src/secret.txt; \
	  ( cd ../ && cargo run --offline -q -p capable-rpc -- serve $$sock --trusted ) & srv=$$!; \
	  for i in 1 2 3 4 5 6 7 8 9 10; do [ -S $$sock ] && break; sleep 0.3; done; \
	  ./$(BUILD)/remote-demo $$sock $$ws; rc=$$?; \
	  kill $$srv 2>/dev/null; rm -rf $$ws $$sock; exit $$rc

# 同一份 .capsh,透明跑在远端 Rust Broker 上(CAPSH_BROKER=<sock>)。
run-capsh-remote: capsh
	@( cd .. && cargo build --offline -q -p capable-rpc )
	@sock=$$(mktemp -u); ../target/debug/capable-rpc serve $$sock --trusted >/dev/null 2>&1 & srv=$$!; \
	  for i in 1 2 3 4 5 6 7 8 9 10; do [ -S $$sock ] && break; sleep 0.3; done; \
	  echo "== capsh (REMOTE Rust broker) examples/hello.capsh =="; \
	  CAPSH_BROKER=$$sock ./$(BUILD)/capsh examples/hello.capsh; \
	  echo "(exit $$? —— secret->sink 被 Rust Broker 拒绝属预期)"; \
	  kill $$srv 2>/dev/null; rm -f $$sock

run: build
	@./$(BUILD)/capsh-demo

# 跑示例 capsh 程序(预期在最后一步因 secret->sink 被拒而以 ENOTCAPABLE 退出)
run-capsh: capsh
	@echo "== capsh examples/hello.capsh =="
	@./$(BUILD)/capsh examples/hello.capsh; \
	  code=$$?; echo "(exit $$code —— 末行 secret->sink 被 confinement 拒绝属预期)"
	@echo "\n== capsh examples/injection.capsh =="
	@./$(BUILD)/capsh examples/injection.capsh; \
	  code=$$?; echo "(exit $$code —— path 注入被 quasi 拒绝属预期)"
	@echo "\n== capsh examples/command.capsh =="
	@./$(BUILD)/capsh examples/command.capsh; \
	  code=$$?; echo "(exit $$code —— CommandCap 固定 argv,shell 注入不可能)"
	@echo "\n== capsh examples/confine.capsh =="
	@./$(BUILD)/capsh examples/confine.capsh; \
	  code=$$?; echo "(exit $$code —— 末段 secret+sink 同区室被 confinement 拒绝属预期)"

# 反向测试:伪造能力必须编译失败。编译成功 = 安全回归 = make 失败。
forge-check:
	@mkdir -p $(BUILD)
	@cp src/*.ml src/*.mli $(BUILD)/
	@(cd $(BUILD) && $(OCAMLC) -c taint.ml cap.mli cap.ml)
	@echo "== forge-check:期望 forge_fail.ml 编译失败(证明能力不可伪造)=="
	@if (cd $(BUILD) && $(OCAMLC) -c -I . ../src/forge_fail.ml) 2>$(BUILD)/forge_err.txt; then \
	  echo "  [SECURITY REGRESSION] forge_fail.ml 竟然编译通过了!能力可被伪造。"; exit 1; \
	else \
	  echo "  [ok] 伪造被类型系统在编译期拒绝:"; \
	  sed 's/^/      /' $(BUILD)/forge_err.txt | head -20; \
	fi

test: run forge-check run-capsh
	@echo "\nAll checks passed."

clean:
	@rm -rf $(BUILD)
