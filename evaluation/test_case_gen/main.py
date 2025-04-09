import re
import os
import subprocess

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.chat_history import BaseChatMessageHistory
from langchain_community.chat_message_histories import ChatMessageHistory
from datetime import datetime


def get_session_id():
    return datetime.strftime(datetime.now(), "%Y_%m_%d_%H_%M_%S")


def get_session_history(session_id: str) -> BaseChatMessageHistory:
    global store
    if session_id not in store:
        store[session_id] = ChatMessageHistory()
    return store[session_id]


def ask_messages(session_id: str, messages) -> str:
    ans = runnable_with_history.invoke(
        messages,
        config={"configurable": {"session_id": session_id}},
    )
    return StrOutputParser().invoke(ans)


def ask(session_id: str, question: str) -> str:
    return ask_messages(session_id, [HumanMessage(content=question)])


def query(session_id: str, messages, query_name: str) -> str:
    if not os.path.exists(f"interflux/{session_id}"):
        os.makedirs(f"interflux/{session_id}")

    if query_name.startswith("debug"):
        with open(f"interflux/{session_id}/messages_{query_name}.txt", "w") as f:
            for msg in messages:
                f.write(f"{msg}\n")

        response = ask_messages(session_id, messages)

        with open(f"interflux/{session_id}/response_{query_name}.txt", "w") as f:
            f.write(response)
        return response
    elif query_name == "origin":
        with open(f"interflux/{session_id}/messages_origin.txt", "w") as f:
            for msg in messages:
                f.write(f"{msg}\n")

        response = ask_messages(session_id, messages)

        with open(f"interflux/{session_id}/response_origin.txt", "w") as f:
            f.write(response)
    else:
        raise ValueError("Invalid query type")

    return response


def parse_response(response: str):
    pkg_install_cmd_pattern = r"<pkg install cmd>\s*(.*?)\s*</pkg install cmd>"
    code_pattern = r"<code>\s*(.*?)\s*</code>"
    compile_cmd_pattern = r"<compile cmd>\s*(.*?)\s*</compile cmd>"
    code_name_pattern = r"<code name>\s*(.*?)\s*</code name>"

    pkg_install_cmd_match = re.search(pkg_install_cmd_pattern, response, re.DOTALL)
    pkg_install_cmd = (
        pkg_install_cmd_match.group(1).strip() if pkg_install_cmd_match else None
    )

    code_match = re.search(code_pattern, response, re.DOTALL)
    code = code_match.group(1).strip() if code_match else None

    code_name_match = re.search(code_name_pattern, response, re.DOTALL)
    code_name = code_name_match.group(1).strip() if code_name_match else None

    compile_cmd_match = re.search(compile_cmd_pattern, response, re.DOTALL)
    compile_cmd = compile_cmd_match.group(1).strip() if compile_cmd_match else None

    if pkg_install_cmd is None:
        raise ValueError("Invalid response: pkg install cmd not found")
    if not code:
        raise ValueError("Invalid response: code not found")
    if not code_name:
        raise ValueError("Invalid response: code name not found")
    if not compile_cmd:
        raise ValueError("Invalid response: compile cmd not found")

    return pkg_install_cmd, code, code_name, compile_cmd


def parse_debug_response(response: str):
    pkg_install_cmd_pattern = r"<pkg install cmd>\s*(.*?)\s*</pkg install cmd>"
    code_pattern = r"<code>\s*(.*?)\s*</code>"
    compile_cmd_pattern = r"<compile cmd>\s*(.*?)\s*</compile cmd>"

    pkg_install_cmd_match = re.search(pkg_install_cmd_pattern, response, re.DOTALL)
    pkg_install_cmd = (
        pkg_install_cmd_match.group(1).strip() if pkg_install_cmd_match else None
    )

    code_match = re.search(code_pattern, response, re.DOTALL)
    code = code_match.group(1).strip() if code_match else None

    compile_cmd_match = re.search(compile_cmd_pattern, response, re.DOTALL)
    compile_cmd = compile_cmd_match.group(1).strip() if compile_cmd_match else None

    if pkg_install_cmd is None:
        raise ValueError("Invalid response: pkg install cmd not found")
    if not code:
        raise ValueError("Invalid response: code not found")
    if not compile_cmd:
        raise ValueError("Invalid response: compile cmd not found")

    return pkg_install_cmd, code, compile_cmd


def store_response(
    session_id: str,
    pkg_install_cmd: str,
    code: str,
    code_name: str,
    compile_cmd: str,
    debug_suffix: str = "",
):
    if not os.path.exists(f"finalvault/{session_id}"):
        os.makedirs(f"finalvault/{session_id}")

    filename_suffix = debug_suffix if debug_suffix else "_origin"
    with open(f"finalvault/{session_id}/pkg_install_cmd" + filename_suffix, "w") as f:
        f.write(pkg_install_cmd)
    with open(f"finalvault/{session_id}/{code_name}" + filename_suffix, "w") as f:
        f.write(code)
    with open(f"finalvault/{session_id}/compile_cmd" + filename_suffix, "w") as f:
        f.write(compile_cmd)

    with open(f"finalvault/{session_id}/pkg_install_cmd", "w") as f:
        f.write(pkg_install_cmd)
    with open(f"finalvault/{session_id}/{code_name}", "w") as f:
        f.write(code)
    with open(f"finalvault/{session_id}/compile_cmd", "w") as f:
        f.write(compile_cmd)
    with open(f"finalvault/{session_id}/code_name", "w") as f:
        f.write(code_name)


def compile_code(
    session_id: str, pkg_install_cmd: str, compile_cmd: str, debug_suffix: str = ""
):
    with open(f"finalvault/{session_id}/pkg_install_cmd" + debug_suffix, "r") as f:
        pkg_install_cmd = f.read()

    if pkg_install_cmd.strip():
        if "-y" not in pkg_install_cmd:
            pkg_install_cmd += " -y"

        print(f"Running: {pkg_install_cmd}")
        print("Installing packages...")

        result = subprocess.run(
            pkg_install_cmd,
            cwd=f"finalvault/{session_id}",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        if result.returncode != 0:
            print(f"Failed to install packages:\n {result.stderr}")
            return result.stderr

    with open(f"finalvault/{session_id}/compile_cmd" + debug_suffix, "r") as f:
        compile_cmd = f.read()

    print(f"Running: {compile_cmd}")
    print("Compiling code...")

    result = subprocess.run(
        compile_cmd,
        cwd=f"finalvault/{session_id}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if result.returncode != 0:
        return result.stderr
    return None


with open("system_prompt.txt", "r") as f:
    system_prompt = f.read()

with open("prompt.txt", "r") as f:
    user_prompt = f.read()

with open("debug_system_prompt.txt", "r") as f:
    debug_system_prompt = f.read()

with open("debug_user_prompt.txt", "r") as f:
    debug_user_prompt = f.read()


store = {}
model = ChatOpenAI(model="o1-mini")

runnable_with_history = RunnableWithMessageHistory(model, get_session_history)

compile_prompt_template = ChatPromptTemplate.from_messages(
    [
        ("system", system_prompt),
        ("user", user_prompt),
    ]
)

debug_prompt_template = ChatPromptTemplate.from_messages(
    [
        ("system", debug_system_prompt),
        ("user", debug_user_prompt),
    ]
)

def ask_origin(target_function, call_trace):
    messages = compile_prompt_template.invoke(
        {"target_function": target_function, "call_trace": call_trace}
    ).to_messages()
    session_id = get_session_id()
    query(session_id, messages, "origin")
    return session_id


def compile_origin(session_id):
    with open(f"interflux/{session_id}/response_origin.txt", "r") as f:
        response = f.read()
    pkg_install_cmd, code, code_name, compile_cmd = parse_response(response)
    store_response(session_id, pkg_install_cmd, code, code_name, compile_cmd, "")
    err_msg = compile_code(session_id, pkg_install_cmd, compile_cmd)
    if not err_msg:
        print("Compile success")
        return None
    print("Compile error:\n", err_msg)
    return err_msg


def run_debug(session_id, installed_pkgs, err_msg, i):
    print(f"Debugging {i}")
    file_suffix = f"_debug_{i-1}" if i > 1 else "_origin"
    with open(f"finalvault/{session_id}/pkg_install_cmd" + file_suffix, "r") as f:
        pkg_install_cmd = f.read()
    with open(f"finalvault/{session_id}/code_name", "r") as f:
        code_name = f.read()
    with open(f"finalvault/{session_id}/{code_name}" + file_suffix, "r") as f:
        code = f.read()
    with open(f"finalvault/{session_id}/compile_cmd" + file_suffix, "r") as f:
        compile_cmd = f.read()

    message = debug_prompt_template.invoke(
        {
            "code": code,
            "code_name": code_name,
            "err_msg": err_msg,
            "installed_pkg": "\n".join(installed_pkgs),
        }
    ).to_messages()
    response = query(session_id, message, f"debug_{i}")


def compile_debug(session_id, installed_pkgs, i):
    with open(f"interflux/{session_id}/response_debug_{i}.txt", "r") as f:
        response = f.read()
    with open(f"finalvault/{session_id}/code_name", "r") as f:
        code_name = f.read()
    pkg_install_cmd, code, compile_cmd = parse_debug_response(response)
    store_response(
        session_id, pkg_install_cmd, code, code_name, compile_cmd, f"_debug_{i}"
    )
    installed_pkgs.append(pkg_install_cmd)
    err_msg = compile_code(session_id, pkg_install_cmd, compile_cmd)
    if not err_msg:
        print("Compile success")
        return None
    print("Compile error:\n", err_msg)
    return err_msg


def do_full_process():
    pass


def do_normal_process(target_function, call_trace, session_id=None):
    if not session_id:
        session_id = ask_origin(target_function, call_trace)

    err_msg = compile_origin(session_id)
    if not err_msg:
        return

    with open(f"finalvault/{session_id}/pkg_install_cmd_origin", "r") as f:
        pkg_install_cmd = f.read()
    installed_pkgs = [
        pkg_install_cmd,
    ]
    i = 1
    while i < 5:
        if not os.path.exists(f"interflux/{session_id}/response_debug_{i}.txt"):
            run_debug(session_id, installed_pkgs, err_msg, i)
        err_msg = compile_debug(session_id, installed_pkgs, i)
        if not err_msg:
            break
        i += 1


if __name__ == "__main__":
    with open("success_list.txt", "r") as f:
        success_list = f.read().splitlines()
        print("Success list:", success_list)

    for entry in os.scandir("startgrid"):
        if entry.is_file():
            function = entry.name
            if function in success_list:
                continue
            with open(entry.path, 'r', encoding='utf-8') as file:
                call_trace = file.read()
            print(f"Processing {function}")
            attempt = 0
            while attempt < 3:
                try:
                    do_normal_process(function, call_trace)
                except Exception as e:
                    print(e)
                    attempt += 1
                else:
                    success_list.append(function)
                    with open("success_list.txt", "a") as f:
                        f.write(function + "\n")
                    print(f"Success: {function}")
                    break
            else:
                print(f"Failed to process {function}")
            


            
