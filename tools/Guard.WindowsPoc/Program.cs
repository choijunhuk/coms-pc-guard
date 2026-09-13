using Guard.WindowsPoc;
using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Execution;

PocCommand? command = PocCommand.Parse(args);
if (command is null) { return (int)PocExitCode.Refused; }
using CancellationTokenSource cancellation = new();
Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; cancellation.Cancel(); };
return (int)await PocNativeController.ExecuteAsync(command, Console.Out, cancellation.Token);
