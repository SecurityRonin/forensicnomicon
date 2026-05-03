.PHONY: test review-feeds feeds-pending

## Run the full workspace test suite
test:
	cargo test --workspace

## Show pending DFIR blog posts awaiting artifact review.
## Run this weekly, then use Claude Code to fetch and analyse each post.
##
##   make review-feeds         → see what's pending
##   /review-dfir-feeds        → Claude Code fetches posts and extracts findings
##
review-feeds:
	@PENDING=archive/sources/pending-review.md; \
	if [ ! -f "$$PENDING" ]; then \
		echo "No pending-review.md found — Feed Watch hasn't run yet."; \
		exit 0; \
	fi; \
	COUNT=$$(grep -c '^\- \[ \]' "$$PENDING" 2>/dev/null || echo 0); \
	echo "Pending DFIR posts awaiting artifact review: $$COUNT"; \
	if [ "$$COUNT" -gt 0 ]; then \
		echo ""; \
		grep '^\- \[ \]' "$$PENDING"; \
		echo ""; \
		echo "Run /review-dfir-feeds in Claude Code to analyse these posts."; \
	fi

## Show pending count only (for CI / status checks)
feeds-pending:
	@grep -c '^\- \[ \]' archive/sources/pending-review.md 2>/dev/null || echo 0
