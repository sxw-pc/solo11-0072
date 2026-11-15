"""保留行号的 SQL 语句切分；能跳过注释与常见字符串形式。"""
from __future__ import annotations
import re
DOLLAR_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")

def strip_comments(sql: str) -> str:
    """将注释替换为空格并保留换行，供保守 token 扫描使用。"""
    out: list[str] = []
    i = 0
    state = "normal"
    quote = ""
    while i < len(sql):
        char = sql[i]
        nxt = sql[i + 1] if i + 1 < len(sql) else ""
        if state == "line":
            if char == "\n":
                state = "normal"
                out.append(char)
            else:
                out.append(" ")
            i += 1
        elif state == "block":
            if char == "*" and nxt == "/":
                out.extend((" ", " "))
                i += 2
                state = "normal"
            else:
                out.append("\n" if char == "\n" else " ")
                i += 1
        elif state == "quote":
            out.append(char)
            if char == quote and nxt == quote:
                out.append(nxt)
                i += 2
            elif char == quote:
                state = "normal"
                i += 1
            else:
                i += 1
        else:
            if char == "-" and nxt == "-":
                out.extend((" ", " "))
                i += 2
                state = "line"
            elif char == "#":
                out.append(" ")
                i += 1
                state = "line"
            elif char == "/" and nxt == "*":
                out.extend((" ", " "))
                i += 2
                state = "block"
            elif char in ("'", '"', "`"):
                state, quote = "quote", char
                out.append(char)
                i += 1
            else:
                out.append(char)
                i += 1
    return "".join(out)

def split_sql(text: str) -> list[tuple[str, int, int]]:
    segments: list[tuple[int, int, str]] = []
    start = 0
    start_line = 1
    line = 1
    state = "normal"
    dollar_tag = ""
    quote = ""
    i = 0
    while i < len(text):
        char = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "normal":
            if char == "-" and nxt == "-":
                state, i = "line", i + 2
            elif char == "#":
                state, i = "line", i + 1
            elif char == "/" and nxt == "*":
                state, i = "block", i + 2
            elif char in ("'", '"', "`"):
                state, quote, i = "quote", char, i + 1
            elif char == "$":
                match = DOLLAR_RE.match(text, i)
                if match:
                    dollar_tag, state, i = match.group(0), "dollar", match.end()
                else:
                    i += 1
            elif char == ";":
                segments.append((start_line, line, text[start:i]))
                start, start_line, i = i + 1, line, i + 1
            else:
                if char == "\n":
                    line += 1
                i += 1
        elif state == "line":
            if char == "\n":
                line += 1
                state = "normal"
            i += 1
        elif state == "block":
            if char == "*" and nxt == "/":
                state, i = "normal", i + 2
            else:
                if char == "\n":
                    line += 1
                i += 1
        elif state == "dollar":
            if text.startswith(dollar_tag, i):
                i += len(dollar_tag)
                state = "normal"
            else:
                if char == "\n":
                    line += 1
                i += 1
        else:
            if char == "\\" and quote == "'" and nxt:
                i += 2
            elif char == quote and nxt == quote:
                i += 2
            elif char == quote:
                state, i = "normal", i + 1
            else:
                if char == "\n":
                    line += 1
                i += 1
    segments.append((start_line, line, text[start:]))
    results: list[tuple[str, int, int]] = []
    for base_line, _end, segment in segments:
        cleaned = strip_comments(segment)
        leading = cleaned[: len(cleaned) - len(cleaned.lstrip())]
        body = cleaned.strip()
        if not body or body == ";":
            continue
        first_line = base_line + leading.count("\n")
        last_line = first_line + cleaned.strip().count("\n")
        results.append((segment.strip(), first_line, last_line))
    return results
