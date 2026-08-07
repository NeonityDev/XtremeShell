using System.Diagnostics;
using System.Text;

namespace XtremeShell.Services
{
    public sealed record CommandResult(int ExitCode, string Output);

    public static class CommandRunner
    {
        public static async Task<string> RunAsync(
            string fileName,
            string arguments,
            CancellationToken cancellationToken = default)
        {
            var result = await RunWithExitCodeAsync(fileName, arguments, cancellationToken);
            return result.Output;
        }

        public static async Task<CommandResult> RunWithExitCodeAsync(
            string fileName,
            string arguments,
            CancellationToken cancellationToken = default)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            var output = new StringBuilder();

            using var process = new Process
            {
                StartInfo = psi,
                EnableRaisingEvents = true
            };

            process.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null)
                    output.AppendLine(e.Data);
            };

            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data != null)
                    output.AppendLine(e.Data);
            };

            if (!process.Start())
                return new CommandResult(-1, "Process could not be started.");

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            try
            {
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                process.WaitForExit();
            }
            catch (OperationCanceledException)
            {
                TryKill(process);
                throw;
            }

            return new CommandResult(process.ExitCode, output.ToString());
        }

        public static int Run(string fileName, string arguments, int? timeoutMilliseconds = null)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false
            };

            using var process = Process.Start(psi);
            if (process == null)
                return -1;

            if (timeoutMilliseconds.HasValue &&
                !process.WaitForExit(timeoutMilliseconds.Value))
            {
                TryKill(process);
                return -1;
            }

            process.WaitForExit();
            return process.ExitCode;
        }

        private static void TryKill(Process process)
        {
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);
            }
            catch
            {
            }
        }
    }
}
