all:
	@echo "---------------------------------------------------------------"
	@echo "[*] Building boot1-extract ..."
	make -C src/boot1-extract
	@echo ""

	@echo "---------------------------------------------------------------"
	@echo "[*] Building es_gettitle_exec poc ..."
	make -C src/es_gettitle_exec
	@echo ""
