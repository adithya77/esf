package sandbox

import "fmt"

// DefaultCommandOutputBytes bounds a command's combined stdout and stderr when
// the operator configures no limit.
const DefaultCommandOutputBytes int64 = 4 << 20

// BoundedCommandScript wraps a rendered command line so each output stream is
// capped inside the sandbox, before a provider's data plane buffers it. FIFOs
// keep the cap streaming; the extra byte distinguishes an exact-limit result
// from overflow. A noisy process receives a closed pipe and the wrapper exits
// 122 after preserving the bounded diagnostic prefix.
func BoundedCommandScript(line string, limit int64) string {
	if limit < 2048 {
		limit = DefaultCommandOutputBytes
	}
	perStream := limit / 2
	return fmt.Sprintf(`
esf_output_dir=$(mktemp -d) || exit 125
trap 'rm -rf "$esf_output_dir"' EXIT
mkfifo "$esf_output_dir/out.pipe" "$esf_output_dir/err.pipe" || exit 125
head -c %d <"$esf_output_dir/out.pipe" >"$esf_output_dir/out" &
esf_out_pid=$!
head -c %d <"$esf_output_dir/err.pipe" >"$esf_output_dir/err" &
esf_err_pid=$!
(
%s
) >"$esf_output_dir/out.pipe" 2>"$esf_output_dir/err.pipe"
esf_exit=$?
wait "$esf_out_pid" || true
wait "$esf_err_pid" || true
head -c %d "$esf_output_dir/out"
head -c %d "$esf_output_dir/err" >&2
esf_out_size=$(wc -c <"$esf_output_dir/out")
esf_err_size=$(wc -c <"$esf_output_dir/err")
if [ "$esf_out_size" -gt %d ] || [ "$esf_err_size" -gt %d ]; then
  printf '\nESF_OUTPUT_LIMIT_EXCEEDED: command output exceeded %d bytes\n' >&2
  exit 122
fi
exit "$esf_exit"`, perStream+1, perStream+1, line, perStream, perStream, perStream, perStream, limit)
}
