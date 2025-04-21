from sys import exit
from threading import Semaphore
from pathlib import Path
from colorama import Fore, Style
import frida


ROOT = Path(__file__).resolve().parent.parent


class TestRunner:
    AGENT_PATH = ROOT / "test" / "agent" / "dist" / "index.js"

    def __init__(self, build_path: Path) -> None:
        self.lock = Semaphore(0)
        self.unity_version = build_path.name
        self.passed = []
        self.failed = []
        self.host = frida.spawn([str(ROOT / "build" / "host"), str(build_path / "out")])

    def prepare(self) -> None:
        session = frida.attach(self.host)

        self.script = session.create_script(
            source=self.AGENT_PATH.read_text(encoding="utf-8")
            .replace("$UNITY_VERSION", self.unity_version)
            .replace(
                "$SOURCE_MAP_PATH",
                str(self.AGENT_PATH.with_name("index.js.map")),
            ),
            name=self.unity_version,
        )
        self.script.on("message", self.on_message)
        self.script.load()

    def run(self) -> None:
        frida.resume(self.host)
        if not self.lock.acquire(timeout=10):
            self.stop()
            raise RuntimeError(f"Timed out when running tests for {self.unity_version}")

    def stop(self) -> None:
        self.lock.release()
        self.script.unload()
        frida.kill(self.host)

    def on_message(self, message: frida.core.ScriptMessage, _):
        if message["type"] == "send" and (payload := message.get("payload")):
            if "name" in payload:
                if "exception" in payload:
                    self.failed.append(payload)
                else:
                    self.passed.append(payload)
            elif action := payload.get("action"):
                getattr(self, action)()


def main() -> int:
    passed_count = 0
    failed_count = 0

    for build_path in (ROOT / "build").iterdir():
        if not build_path.is_dir():
            continue

        test_runner = TestRunner(build_path=build_path)
        test_runner.prepare()
        print(f"{Fore.BLUE}►{Style.RESET_ALL} {test_runner.unity_version}")
        test_runner.run()

        for passed in test_runner.passed:
            passed_count += 1
            print(f"  {Fore.GREEN}✓ {passed['name']}{Style.RESET_ALL}")
        for failed in test_runner.failed:
            failed_count += 1
            print(
                f"  {Fore.RED}𐄂 {failed['name']}: {str(failed['exception'])}{Style.RESET_ALL}"
            )

    if failed_count > 0:
        print(f"{Fore.RED}𐄂{Style.RESET_ALL} {failed_count} test(s) failed")
        return 1
    else:
        print(f"{Fore.BLUE}✓{Style.RESET_ALL} {passed_count} test(s) passed")
        return 0


if __name__ == "__main__":
    exit(main())
