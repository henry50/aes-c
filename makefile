aesbuild:
	@gcc -g -o aes aes.c util.c --all --ansi
	@echo "Make finished"