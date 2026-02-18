import * as vscode from 'vscode';
import { execFile } from 'child_process';
import * as path from 'path';

interface SarifResult {
  ruleId: string;
  message: { text: string };
  level: string;
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number; startColumn?: number };
    };
  }>;
}

interface SarifRun {
  results: SarifResult[];
}

interface SarifLog {
  runs: SarifRun[];
}

const diagnosticCollection = vscode.languages.createDiagnosticCollection('rustdefend');

export function activate(context: vscode.ExtensionContext): void {
  const scanCommand = vscode.commands.registerCommand('rustdefend.scan', () => {
    runScan();
  });

  context.subscriptions.push(scanCommand);
  context.subscriptions.push(diagnosticCollection);

  // Scan on save if configured
  const onSave = vscode.workspace.onDidSaveTextDocument((doc) => {
    const config = vscode.workspace.getConfiguration('rustdefend');
    if (config.get<boolean>('scanOnSave') && doc.languageId === 'rust') {
      runScan();
    }
  });
  context.subscriptions.push(onSave);
}

function runScan(): void {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showWarningMessage('RustDefend: No workspace folder open');
    return;
  }

  const workspaceRoot = workspaceFolders[0].uri.fsPath;
  const config = vscode.workspace.getConfiguration('rustdefend');
  const binaryPath = config.get<string>('binaryPath') || 'rustdefend';
  const extraArgs = config.get<string[]>('extraArgs') || [];

  const args = ['scan', workspaceRoot, '--format', 'sarif', ...extraArgs];

  vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'RustDefend: Scanning...' },
    () =>
      new Promise<void>((resolve) => {
        execFile(binaryPath, args, { maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
          diagnosticCollection.clear();

          if (stderr) {
            // stderr may contain info messages, not necessarily errors
            console.log('RustDefend stderr:', stderr);
          }

          if (!stdout.trim()) {
            vscode.window.showInformationMessage('RustDefend: No findings');
            resolve();
            return;
          }

          try {
            const sarif: SarifLog = JSON.parse(stdout);
            const diagnosticMap = new Map<string, vscode.Diagnostic[]>();

            for (const run of sarif.runs || []) {
              for (const result of run.results || []) {
                const loc = result.locations?.[0]?.physicalLocation;
                if (!loc) continue;

                const fileUri = loc.artifactLocation.uri;
                const filePath = fileUri.startsWith('file://')
                  ? fileUri.slice(7)
                  : path.resolve(workspaceRoot, fileUri);

                const line = (loc.region?.startLine || 1) - 1;
                const col = (loc.region?.startColumn || 1) - 1;

                const severity = levelToSeverity(result.level);
                const diagnostic = new vscode.Diagnostic(
                  new vscode.Range(line, col, line, col + 80),
                  `[${result.ruleId}] ${result.message.text}`,
                  severity
                );
                diagnostic.source = 'rustdefend';

                const key = filePath;
                if (!diagnosticMap.has(key)) {
                  diagnosticMap.set(key, []);
                }
                diagnosticMap.get(key)!.push(diagnostic);
              }
            }

            for (const [filePath, diags] of diagnosticMap) {
              diagnosticCollection.set(vscode.Uri.file(filePath), diags);
            }

            const totalFindings = Array.from(diagnosticMap.values()).reduce(
              (sum, d) => sum + d.length,
              0
            );
            vscode.window.showInformationMessage(
              `RustDefend: ${totalFindings} finding(s) across ${diagnosticMap.size} file(s)`
            );
          } catch (parseError) {
            vscode.window.showErrorMessage(
              `RustDefend: Failed to parse output — ${parseError}`
            );
          }

          resolve();
        });
      })
  );
}

function levelToSeverity(level: string): vscode.DiagnosticSeverity {
  switch (level) {
    case 'error':
      return vscode.DiagnosticSeverity.Error;
    case 'warning':
      return vscode.DiagnosticSeverity.Warning;
    case 'note':
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}

export function deactivate(): void {
  diagnosticCollection.dispose();
}
