from os import environ
from threading import Semaphore
from pathlib import Path
from colorama import Fore, Style
import frida
import docker


ROOT = Path(__file__).resolve().parent.parent
AGENT_PATH = ROOT / "test" / "agent" / "dist" / "index.js"
SOURCE_MAP_PATH = AGENT_PATH.with_name("index.js.map")


class TestRunner:
    def __init__(
        self,
        name: str,
        device: frida.core.Device,
        spawn_args: list[str],
        script_variables: dict,
    ) -> None:
        self.lock = Semaphore(0)
        self.passed = []
        self.failed = []
        self.name = name
        self.script_variables = script_variables
        self.device = device
        self.host = device.spawn(spawn_args)

    def prepare(self) -> None:
        session = self.device.attach(self.host)

        source = AGENT_PATH.read_text(encoding="utf-8")
        for key, value in self.script_variables.items():
            source = source.replace(f"${key}", value)

        self.script = session.create_script(source=source, name="source")
        self.script.on("message", self.on_message)
        self.script.load()

    def run(self) -> None:
        self.device.resume(self.host)
        if not self.lock.acquire(timeout=10):
            self.stop()
            raise RuntimeError(f"Timed out when running tests for {self.name}")

    def stop(self) -> None:
        self.lock.release()
        self.script.unload()
        self.device.kill(self.host)

    def on_message(self, message: frida.core.ScriptMessage, _):
        if message["type"] == "send" and (payload := message.get("payload")):
            if "name" in payload:
                if "exception" in payload:
                    self.failed.append(payload)
                else:
                    self.passed.append(payload)
            elif action := payload.get("action"):
                getattr(self, action)()
        elif message["type"] == "error":
            if stack := message.get("stack"):
                print(stack)
            else:
                print(message["description"])


# TOOD: refactor this spaghetti crap
def main(use_docker: bool) -> int:
    passed_count = 0
    failed_count = 0

    if use_docker:
        client = docker.from_env()

        containers = [
            client.containers.run(
                image=image,
                ports={"27042/tcp": None},
                volumes=[f"{SOURCE_MAP_PATH}/:/tmp/index.js.map"],
                security_opt=["seccomp:unconfined"],
                detach=True,
            ) for image in client.images.list("frida-il2cpp-bridge-playground")
        ]

        if not containers:
            print("No Docker images available, please build them with `make image UNITY_VERSION=...`")

        for container in containers:
            container.reload()

        test_runners = [
            TestRunner(
                name=container.image.tags[0].split(":")[1],
                device=frida.get_device_manager() \
                    .add_remote_device("localhost:" + container.ports["27042/tcp"][0]["HostPort"]),
                script_variables=dict(
                    UNITY_VERSION=container.image.tags[0].split(":")[1],
                    SOURCE_MAP_PATH="/tmp/index.js.map",
                ),
                spawn_args=["./build/host", f"./build/{container.image.tags[0].split(":")[1]}/out"],
            ) for container in containers
        ]
    else:
        test_runners = [
            TestRunner(
                name=build_path.name,
                device=frida.get_local_device(),
                script_variables=dict(
                    UNITY_VERSION=build_path.name,
                    SOURCE_MAP_PATH=str(SOURCE_MAP_PATH),
                ),
                spawn_args=[str(ROOT / "build" / "host"), str(build_path / "out")],
            ) for build_path in (ROOT / "build").iterdir() if build_path.is_dir()
        ]

    for test_runner in test_runners:
        test_runner.prepare()
        print(f"{Fore.BLUE}►{Style.RESET_ALL} {test_runner.name}")
        test_runner.run()

        for passed in test_runner.passed:
            passed_count += 1
            print(f"  {Fore.GREEN}✓ {passed['name']}{Style.RESET_ALL}")
        for failed in test_runner.failed:
            failed_count += 1
            print(
                f"  {Fore.RED}𐄂 {failed['name']}: {str(failed['exception'])}{Style.RESET_ALL}"
            )

    if use_docker:
        for container in containers:
            container.remove(force=True)

    if failed_count > 0:
        print(f"{Fore.RED}𐄂{Style.RESET_ALL} {failed_count} test(s) failed")
        return 1
    else:
        print(f"{Fore.BLUE}✓{Style.RESET_ALL} {passed_count} test(s) passed")
        return 0


if __name__ == "__main__":
    exit(main(use_docker="DOCKER_HOST" in environ))
