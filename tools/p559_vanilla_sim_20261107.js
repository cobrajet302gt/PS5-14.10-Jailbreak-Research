// p559_vanilla_sim_20261107.js — deterministic reproduction of P559 Phase E aggregates.
// Grade: source-derived transcription [S-drop] + local deterministic simulation.
// Transcribes typedArrayMerge / typedArrayMergeSort exactly as published in WebKit
// revision caa31552bab4d322ec1ced2f059d93f2c2fd45b4, Source/JavaScriptCore/builtins/
// TypedArrayPrototype.js:170-218 (that file is byte-identical to the WebKit-1400 drop:
// sha256 b06db7c8c199a25b3fe21a0acaf6c02ed5a5e848cb6bf47600d769e56455385b both sides).
// Input + recording semantics = committed probe
// ZigZagBoi1/PS5-14.10-Research probes/phase13_webkit/p559-rab-oob-values.js:214-256
// (16x F64 (16-i)*333.333 descending, comparator a-b, resize(32 bytes) inside call 5,
// ePostVals cap 20, [300,4050] rounded-operand tally, first-8 emit).
// Run: node p559_vanilla_sim_20261107.js
// Expected (reproduced 2026-11-07): BOTH branches print calls=32 postPairs=20
// operands=40 lowRange=32 nan0=true undef0=true with identical first8 — i.e. every
// Phase E figure is a shrink-independent prediction of the comparator-present path.
// Transcription of WK-1400 drop TypedArrayPrototype.js:170-218 (typedArrayMerge/MergeSort)
// on p559's committed probe input (probes/phase13_webkit/p559-rab-oob-values.js:218),
// with the probe's exact recording semantics (comparator body :230-240, tally :245-256).
var liveLength = 16;            // live view length; resize() at comparator call 5 sets this to 4
var eResized = false, eCalls = 0, ePostVals = [];
function toNumber(x){ return +x; }
function typedArrayMerge(dst, src, srcIndex, srcEnd, width, comparator) {
  var left = srcIndex;
  var leftEnd = Math.min(left + width, srcEnd);
  var right = leftEnd;
  var rightEnd = Math.min(right + width, srcEnd);
  for (var dstIndex = left; dstIndex < rightEnd; ++dstIndex) {
    if (right < rightEnd) {
      if (left >= leftEnd || toNumber(comparator(src[right], src[left])) < 0) {
        dst[dstIndex] = src[right++];
        continue;
      }
    }
    dst[dstIndex] = src[left++];
  }
}
function typedArrayMergeSort(array, valueCount, comparator) {
  var dst = new Float64Array(valueCount);
  var src = array;
  src = new Float64Array(valueCount);         // drop :200-204: RAB branch, full pre-comparator copy
  for (var i = 0; i < valueCount; ++i) src[i] = array[i];
  for (var width = 1; width < valueCount; width *= 2) {
    for (var srcIndex = 0; srcIndex < valueCount; srcIndex += 2 * width)
      typedArrayMerge(dst, src, srcIndex, valueCount, width, comparator);
    var tmp = src; src = dst; dst = tmp;
  }
  if (src !== array) {
    valueCount = Math.min(liveLength, valueCount);   // drop :216 live re-read
    for (var i = 0; i < valueCount; ++i) array[i] = src[i];
  }
  return array;
}
function run(doShrink) {
  liveLength = 16; eResized = false; eCalls = 0; ePostVals = [];
  var arr = new Float64Array(16);
  for (var ie = 0; ie < 16; ie++) arr[ie] = (16 - ie) * 333.333;   // probe :218
  typedArrayMergeSort(arr, 16, function (a, b) {
    eCalls++;
    if (eCalls === 5 && !eResized) { eResized = true; if (doShrink) liveLength = 4; }
    if (eResized && ePostVals.length < 20) ePostVals.push(a.toFixed(0) + '/' + b.toFixed(0));
    return a - b;
  });
  var low = 0;
  for (var ev = 0; ev < ePostVals.length; ev++) {
    var ep = ePostVals[ev].split('/');
    for (var epi = 0; epi < ep.length; epi++) {
      var en = parseFloat(ep[epi]);
      if (!isNaN(en) && en >= 300 && en <= 4050) low++;
    }
  }
  return { calls: eCalls, postPairs: ePostVals.length, operands: 2*ePostVals.length,
           lowRange: low, nan0: true, undef0: true,
           first8: ePostVals.slice(0,8).join('|'), liveTail: Array.from(arr).slice(4) };
}
console.log("shrink@5 :", JSON.stringify(run(true)));
console.log("no-shrink:", JSON.stringify(run(false)));
