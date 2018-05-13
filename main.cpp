//a = 5
//a = 5.243
//a = 2
//print(b=5,3)
//{a=1;{a=3;print(a);}print a;}
//foo(a,b)=>a+3
//foo = (a,b) => a+3
//foo = (a,b) => { a + 3; a-3; }
//library stuff
void print(const char* fmt, ...);
void error(const char* fmt, ...);
extern "C" { size_t strlen(const char* str); }
extern "C" { int strcmp(const char* str1, const char* str2); }
typedef long long s64; typedef unsigned long long u64;
typedef int s32; typedef unsigned int u32; 
typedef float f32;
u64 str_hash(const char* str, size_t len) {
	u64 x = 0xcbf29ce484222325ull;
	for (u32 i = 0; i < len; ++i) {
		x ^= str[i]; x *= 0x100000001b3ull; x ^= x >> 32;
	}
	return x;
}
u64 hash(const char* str) { return str_hash(str, strlen(str)); }
u64 hash(u64 v) { return v; }
template <typename K, typename V> struct Map {
	K* keys; V* vals;
	u32 len, cap;
	void clear() { delete[] keys; delete[] vals; *this = {}; }
	V* get(K key) {
		if (len == 0) return nullptr;
		u64 i = hash(key);
		while (true) {
			i &= cap - 1;
			if (keys[i] == key)
				return &vals[i];
			else if (!keys[i])
				return nullptr;
			++i;
		}
		return nullptr;
	}
	void grow() {
		u32 newcap = cap * 2 < 16 ? 16 : cap * 2;
		Map new_map = { new K[newcap]{}, new V[newcap]{}, 0, newcap };
		for (u32 i = 0; i < cap; ++i)
			if (keys[i])
				new_map.put(keys[i], vals[i]);
		delete[] keys; delete[] vals;
		*this = new_map;
	}
	void put(K key, V val) {
		if (2 * len >= cap)
			grow();
		u64 i = hash(key);
		while (true) {
			i &= cap - 1;
			if (keys[i] == key) {
				vals[i] = val; return;
			}
			else if (!keys[i]) {
				++len; keys[i] = key; vals[i] = val; return;
			}
			++i;
		}
	}
};
template <typename T> struct Vector {
	T* items; u32 len, cap;
	T* begin() { return items; }
	T& back() { return items[len - 1]; }
	T* end() { return items + len; }
	void push(T item) {
		if (len >= cap) {
			cap = cap * 2 < 16 ? 16 : cap * 2;
			T* newitems = new T[cap]{};
			if (items)
				for (u32 i = 0; i < len; ++i)
					newitems[i] = items[i];
			items = newitems;
		}
		items[len++] = item;
	}
	void pop() { if (len > 0) { --len; } }
};
template <typename T> struct Pool {
	T* items; u32 len;
	T* push(T item) {
		if (len == 0 || len >= 32) {
			items = new T[32]{}; len = 0;
		}
		items[len++] = item; return &items[len - 1];
	}
};

//string interning
Map<u64,char*> strs{};
const char* internstr(const char* beg, const char* end) {
	u32 len = (u32)(end - beg);
	u64 hash = str_hash(beg, len);
	if (char** existingstr = strs.get(hash))
		return *existingstr;
	char* str = new char[len + 1];
	for (char* t = str; beg != end; ++beg, ++t) *t = *beg;
	str[len] = 0;
	strs.put(hash, str);
	return str;
}
const char* internstr(const char* str) { return internstr(str, str + strlen(str)); }

//tokeniser
enum class TokenType { LPR, RPR, GT, LT, EQEQ, LTEQ, GTEQ, NEQ, ADD, SUB, MUL, DIV, MOD, INT, ID, EQ, EOF, COMMA, LBR, RBR, SC, IF, ELIF, ELSE, WHILE, FUNC };
struct Token { TokenType type; int val; const char* str; const char* stream; } token;
const char *streambeg, *stream;
#define TOK(cv,t) if (c == cv) { ++stream; token.type = TokenType::t; return; }
#define TOK2(cv,t) if (c == cv[0] && stream[1] == cv[1]) { stream += 2; token.type = TokenType::t; return; }
#define KEYW(s,t) if (strcmp(s, token.str) == 0) { token.type = TokenType::t; return; }
void nexttoken() {
	token = {};
	char c = *stream;
	token.stream = stream;
	while (c == ' ' || c == '\t' || c == '\n') { ++stream; c = *stream; }
	if (c >= '0' && c <= '9') {
		int num = 0;
		while (c >= '0' && c <= '9') {
			num *= 10; num += c - '0'; ++stream; c = *stream;
		}
		token.type = TokenType::INT; token.val = num; return;
	}
	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		const char* start = stream; ++stream; c = *stream;
		while ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') { ++stream; c = *stream; }
		token.str = internstr(start, stream); 
		KEYW("if", IF) KEYW("elif", ELIF) KEYW("else", ELSE) KEYW("while", WHILE) KEYW("func", FUNC)
		token.type = TokenType::ID; return;
	}
	TOK2("==", EQEQ) TOK2("<=", LTEQ) TOK2(">=", GTEQ) TOK2("!=", NEQ)
	TOK('>', GT) TOK('<', LT)
	TOK('+', ADD) TOK('-', SUB) TOK('*', MUL) TOK('/', DIV) TOK('%', MOD) TOK('(', LPR) TOK(')', RPR)
	TOK('\0', EOF) TOK('=', EQ) TOK(',', COMMA) TOK('{', LBR) TOK('}', RBR) TOK(';', SC)
	error("Unknown symbol %c", c);
}
void expect(TokenType type, const char* c) {
	if (token.type != type) error("Expected %s", c);
	nexttoken();
}
bool match(TokenType type) {
	if (token.type == type) { nexttoken(); return true; }
	return false;
}

//parser
enum class ExprType { VAR, VAL, BINARY, CALL, FUNC, ASSIGN, BLOCK, IF, WHILE };
struct Expr;
struct CondBlock { Expr* cond; Expr* block; };
enum class ValueType { VOID, s32, f32 };
struct Value {
	ValueType type;
	union {
		int s32;
		float f32;
	};
	Value() : type(ValueType::VOID) {}
	Value(int val) : type(ValueType::s32), s32(val) {}
	Value(float val) : type(ValueType::f32), f32(val) {}
};
struct Expr {
	ExprType type;
	union {
		const char* varname;
		Value val;
		struct { TokenType op; Expr *l, *r; } binary;
		struct { const char* funcname; Vector<Expr*> args; } call;
		struct { const char* funcname; Vector<const char*> params; Expr* block; } func;
		struct { const char* varname; Expr* e; } assign;
		Vector<Expr*> block;
		struct { Vector<CondBlock> conds; Expr* elseblock; } ifexpr;
		CondBlock whileexpr;
	};
	Expr() {}
	Expr(Value v) : type(ExprType::VAL), val(v) {}
	Expr(TokenType op, Expr* l, Expr* r) : type(ExprType::BINARY), binary({ op, l, r }) {}
	Expr(const char* varname) : type(ExprType::VAR), varname(varname) {}
	Expr(const char* funcname, Vector<Expr*>& args) : type(ExprType::CALL), call({ funcname, args }) {}
	Expr(const char* funcname, Vector<const char*>& params, Expr* block) : type(ExprType::FUNC), func({ funcname, params, block }) {}
	Expr(const char* varname, Expr* assign) : type(ExprType::ASSIGN), assign({varname, assign}) {}
	Expr(Vector<Expr*>& block) : type(ExprType::BLOCK), block(block) {}
	Expr(Vector<CondBlock>& conds, Expr* elseblock) : type(ExprType::IF), ifexpr({ conds, elseblock }) {}
	Expr(Expr* cond, Expr* block) : type(ExprType::WHILE), whileexpr({ cond, block }) {}
};
Pool<Expr> exprs{};
Expr* parse_expr();
Expr* parse_binary() {
	if (match(TokenType::LBR)) {//scope block
		Vector<Expr*> block{};
		while (token.type != TokenType::RBR && token.type != TokenType::EOF) {
			block.push(parse_expr());
			expect(TokenType::SC, ";");
		}
		expect(TokenType::RBR, "}");
		return exprs.push(Expr(block));
	}
	else if (match(TokenType::LPR)) {//parens
		Expr* expr = parse_expr();
		expect(TokenType::RPR, ")");
		return expr;
	}
	else if (token.type == TokenType::INT) {
		Token t = token; nexttoken();
		return exprs.push(Expr(t.val));
	}
	else if (token.type == TokenType::ID) {
		Token t = token; nexttoken();
		if (match(TokenType::LPR)) {//func call
			Vector<Expr*> args{};
			if (token.type != TokenType::RPR) {
				args.push(parse_expr());
				while (match(TokenType::COMMA))
					args.push(parse_expr());
			}
			expect(TokenType::RPR, ")");
			return exprs.push(Expr(t.str, args));
		}
		else if (match(TokenType::EQ)) {//assign
			return exprs.push(Expr(t.str, parse_expr()));
		}
		else//var
			return exprs.push(Expr(t.str));
	}
	else if (match(TokenType::IF)) {
		expect(TokenType::LPR, "("); 
		Expr* ifexpr = parse_expr(); 
		expect(TokenType::RPR, ")");
		Expr* thenexpr = parse_expr();
		Vector<CondBlock> conds{};
		conds.push({ ifexpr, thenexpr });
		while (match(TokenType::ELIF)) {
			expect(TokenType::LPR, "(");
			ifexpr = parse_expr();
			expect(TokenType::RPR, ")");
			thenexpr = parse_expr();
			conds.push({ ifexpr, thenexpr });
		}
		Expr* elseexp = match(TokenType::ELSE) ? parse_expr() : nullptr;
		return exprs.push(Expr(conds, elseexp));
	}
	else if (match(TokenType::WHILE)) {
		expect(TokenType::LPR, "(");
		Expr* cond = parse_expr();
		expect(TokenType::RPR, ")");
		Expr* block = parse_expr();
		return exprs.push(Expr(cond, block));
	}
	else if (match(TokenType::FUNC)) {
		if (token.type != TokenType::ID) error("Expected function name");
		const char* name = token.str; nexttoken();
		Vector<const char*> parms{};
		expect(TokenType::LPR, "(");
		if (token.type == TokenType::ID) {
			parms.push(token.str); nexttoken();
			while (match(TokenType::COMMA)) {
				if (token.type != TokenType::ID) error("Expected arg name");
				parms.push(token.str); nexttoken();
			}
		}
		expect(TokenType::RPR, ")");
		return exprs.push(Expr(name, parms, parse_expr()));
	}
	error("Unhandled token type %d", token.type); return nullptr;
}
Expr* parse_unary(TokenType p = TokenType::GT) {
	if (p == TokenType::INT)
		return parse_binary();
	TokenType np = (TokenType)((int)p + 1);
	Expr* expr = parse_unary(np);
	while (match(p))
		expr = exprs.push(Expr(p, expr, parse_unary(np)));
	return expr;
}
Expr* parse_expr() {
	return parse_unary();
}

//interpreter from this point!
struct Function {
	Function(int numargs, Value(*FuncCallback)(int argc, Value* args)) : isnative(true), native({ numargs, FuncCallback }) {}
	Function(Vector<const char*> params, Expr* block) : isnative(false), lambda({ params, block }) {}
	Function() {}
	union {
		struct { int numargs; Value(*FuncCallback)(int argc, Value* args); } native;
		struct { Vector<const char*> args; Expr* block; } lambda;
	};
	bool isnative;
};
struct Env {
	Map<const char*, Function> funcs; Map<const char*, Value> vars;
};
Vector<Env> envs;
Value* getvar(const char* name) {
	for (int i = envs.len - 1; i >= 0; --i)
		if (Value* value = envs.items[i].vars.get(name))
			return value;
	return nullptr;
}
Value setvar(const char* name, Value val) {
	if (Value* value = getvar(name))
		*value = val;
	envs.back().vars.put(name, val);
	return val;
}
Function* getfunc(const char* name) {
	for (int i = envs.len - 1; i >= 0; --i)
		if (Function* func = envs.items[i].funcs.get(name))
			return func;
	return nullptr;
}
void setfunc(const char* name, Function val) {
	if (getfunc(name)) error("Already defined function %s", name);
	envs.back().funcs.put(name, val);
}
void pushenv() { envs.push({}); }
void popenv() { envs.back().funcs.clear(); envs.back().vars.clear(); envs.pop(); }

template <typename T> T cast_val(Value v) {
	if (v.type == ValueType::s32) return (T)v.s32;
	if (v.type == ValueType::f32) return (T)v.f32;
	error("Cannot cast void value");
	return T();
}
template <typename T> Value eval_op(TokenType op, Value l, Value r) {
	T lv = cast_val<T>(l), rv = cast_val<T>(r);
	if (op == TokenType::ADD) return lv + rv;
	if (op == TokenType::SUB) return lv - rv;
	if (op == TokenType::MUL) return lv * rv;
	if (op == TokenType::DIV) return lv / rv;
	if (op == TokenType::GT) return lv > rv;
	if (op == TokenType::LT) return lv < rv;
	if (op == TokenType::EQEQ) return lv == rv;
	if (op == TokenType::LTEQ) return lv <= rv;
	if (op == TokenType::GTEQ) return lv >= rv;
	if (op == TokenType::NEQ) return lv != rv;
	error("Illegal op %d for type %d", op, l.type);
	return Value();
}
template<typename T> Value eval_op_int(TokenType op, Value l, Value r) {
	if (op == TokenType::MOD) return cast_val<T>(l) % cast_val<T>(r);
	return eval_op<T>(op, l, r);
}

Value eval_expr(Expr* e) {
	if (!e) { return 0; }
	if (e->type == ExprType::VAR) {
		if (Value* val = getvar(e->varname))
			return *val;
		error("Unknown variable %s", e->varname);
	}
	else if (e->type == ExprType::VAL) return e->val;
	else if (e->type == ExprType::BINARY) {
		Value l = eval_expr(e->binary.l); Value r = eval_expr(e->binary.r);
		if (l.type == ValueType::s32) return eval_op_int<s32>(e->binary.op, l, r);
		if (l.type == ValueType::f32) return eval_op<f32>(e->binary.op, l, r);
		error("Cannot apply operator to void");
	}
	else if (e->type == ExprType::CALL) {
		Function* func = getfunc(e->call.funcname);
		if (!func) error("Undefined function %s", e->call.funcname);
		
		int numargs = -1;
		if (func->isnative && func->native.numargs != -1) numargs = func->native.numargs;
		else if (!func->isnative) numargs = func->lambda.args.len;
		if (numargs != -1 && numargs != e->call.args.len) error("Expected %d args got %d", numargs, e->call.args.len);

		if (func->isnative) {
			Value* vals = new Value[e->call.args.len];
			for (u32 i = 0; i < e->call.args.len; ++i)
				vals[i] = eval_expr(e->call.args.items[i]);
			Value val = func->native.FuncCallback(e->call.args.len, vals);
			delete[] vals;
			return val;
		}
		else {
			pushenv();
			for (u32 i = 0; i < e->call.args.len; ++i)
				setvar(func->lambda.args.items[i], eval_expr(e->call.args.items[i]));
			Value val = eval_expr(func->lambda.block);
			popenv();
			return val;
		}
	}
	else if (e->type == ExprType::FUNC) { setfunc(e->func.funcname, Function(e->func.params, e->func.block)); return Value(); }
	else if (e->type == ExprType::ASSIGN) return setvar(e->assign.varname, eval_expr(e->assign.e));
	else if (e->type == ExprType::BLOCK) {
		pushenv();
		Value lastval;
		for (Expr* ce : e->block)
			lastval = eval_expr(ce);
		popenv();
		return lastval;
	}
	else if (e->type == ExprType::IF) {
		for (CondBlock& cond : e->ifexpr.conds)
			if (cast_val<s32>(eval_expr(cond.cond)) != 0)
				return eval_expr(cond.block);
		if (e->ifexpr.elseblock)
			return eval_expr(e->ifexpr.elseblock);
		return Value();
	}
	else if (e->type == ExprType::WHILE) {
		while (cast_val<s32>(eval_expr(e->whileexpr.cond)) != 0)
			eval_expr(e->whileexpr.block);
		return Value();
	}
	error("Unknown eval");
	return Value();
}
Value eval(const char* str) {
	streambeg = stream = str; nexttoken(); 
	Expr* e = parse_expr();
	Value val = eval_expr(e);
	return val;
}

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdarg.h>
#include <cassert>
#include <stdlib.h>
#include <cstring>

extern "C" { __declspec(dllimport) void __stdcall OutputDebugStringA(const char* str); }
void print(const char* fmt, va_list args) {
	static char errbuf[1024];
	vsnprintf(errbuf, 1024, fmt, args);
	OutputDebugStringA(errbuf);
}
void print(const char* fmt, ...) {
	va_list args; va_start(args, fmt); print(fmt, args); va_end(args);
}
void error(const char* fmt, ...) {
	va_list args;
	va_start(args, fmt); 
	print("Error: ");
	print(fmt, args); 
	va_end(args);
	int line = 0, lineoff = 0;
	if (token.stream) {
		const char* linestart = streambeg, *lineend = streambeg;
		for (const char* s = streambeg; s != token.stream; ++s, ++lineoff) {
			if (*s == '\n') { ++line; lineoff = 0; linestart = s + 1; }
		}
		for (lineend = linestart; *lineend != '\0' && *lineend != '\n'; ++lineend);
		print(" at %d:%d\n%.*s\n", line + 1, lineoff, lineend - linestart, linestart);
		for (int i = 0; i < lineoff; ++i) print(" ");
		print("^\n");
	}
	__debugbreak();
	exit(1);
}

void test_expr(const char* s, int v) { print("%s\n", s); Value a = eval(s); if (!((v == 0 && a.type == ValueType::VOID) || cast_val<int>(a) == v)) __debugbreak(); }
void test() {
	test_expr("{ func fib(n) if (n > 1) n+fib(n-1) else 1; fib(3); }", 6);
	test_expr("print(b=5,3)", 0);
	test_expr("3+3>=6", 1);
	test_expr("{ func x(n) n+1; x(3); }", 4);
	test_expr("13%10==3", 1);
	test_expr("{ x = 3; while (x > 0) { x = x - 1; }; }", 0);
	test_expr("if (3 > 1) 1", 1);
	test_expr("if (3 > 4) 1 else 2", 2);
	test_expr("if (3 > 4) 1 elif (5 > 1) 2 else 3", 2);
	test_expr("{ x = 3; print(x); }", 0);
	test_expr("{ x = 3; }", 3);
	test_expr("{ x = 3; x; }", 3);
	test_expr("(3*4)+5", 17);
	test_expr("(3+(5-2) \t\n )", 6);
	test_expr("(3)", 3);
	test_expr("  5 +   3 \t", 8);
	test_expr("5*3", 15);
	test_expr("15/3*4", 20);
	test_expr("4+3*3", 13);
	test_expr("3+2+1", 6);
	test_expr("10", 10);
	test_expr("245645432", 245645432);
	assert(internstr("a") == internstr("a"));
	assert(internstr("a") != internstr("b"));
	assert(internstr("a") != "a");
	assert(internstr("fjfjf") == internstr("fjfjf"));
	assert(internstr(internstr("a")) == internstr("a"));
	streambeg = stream = "foo"; nexttoken();
}
int main(int argc, char** argv) {
	pushenv(); 
	setfunc(internstr("print"), Function(-1, [](int argc, Value* args) {
		for (int i = 0; i < argc; ++i)
			print("%d ", cast_val<s32>(args[i]));
		print("\n");
		return Value();
	}));
	test();
	
	return 0;
}
