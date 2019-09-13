from datetime import datetime

def parse(data):
	def _append_text(data):
		if data["text"] is not None:
			if data["symbol"]:
				if data["text"] == "#f":
					value = None
				else:
					value = data["text"]

					try:
						value = float(data["text"])
					except ValueError:
						pass
			else:
				value = data["text"].decode("utf-8")

				try:
					value = datetime.strptime(data["text"], "%Y-%m-%d %H:%M:%S")
				except ValueError:
					pass

			data["text"] = value
			data["values"].append(data["text"])
			data["text"] = None
		data["symbol"] = True

	def _pair_values(data):
		if len(data) == 3 and data[1] == ".":
			return (data[0], data[2])
		return data

	stack = [{"text": None, "symbol": True, "values": []}]
	in_str = False

	for c in data:
		if c == '"':
			if not in_str:
				stack[-1]["text"] = ""
				stack[-1]["symbol"] = False
			in_str = not in_str
		elif in_str:
			stack[-1]["text"] += c
		elif c == "(":
			stack.append({"text": None, "symbol": True, "values": []})
		elif c == ")":
			assert len(stack) > 1

			_append_text(stack[-1])

			if len(stack) == 2:
				return _pair_values(stack[1]["values"])
			else:
				stack[-2]["values"].append(_pair_values(stack[-1]["values"]))

			stack.pop()
		elif c == ' ' or c == '\r' or c == '\n':
			_append_text(stack[-1])
		else:
			if stack[-1]["text"] is None:
				stack[-1]["text"] = c
			else:
				stack[-1]["text"] += c

	if stack[0]["values"]:
		_append_text(stack[-1])

		return _pair_values(stack[0]["values"])
	else:
		return None

def format(data):
	if data is None:
		return "#f"
	elif type(data) == list:
		return "(" + " ".join([format(x) for x in data]) + ")"
	elif type(data) == tuple:
		return "(" + " . ".join([format(x) for x in data]) + ")"
	elif type(data) == int or type(data) == float:
		return str(data)
	elif type(data) == str:
		return data
	else:
		return '"' + str(data) + '"'
