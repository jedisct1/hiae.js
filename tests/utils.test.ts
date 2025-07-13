import { expect, test } from "bun:test";
import { ctEq, LE64, tail, truncate, xor, zeroPad } from "../src/utils.js";

test("LE64 encoding", () => {
  const value = 0x0123456789abcdefn;
  const expected = new Uint8Array([0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]);
  expect(LE64(value)).toEqual(expected);
});

test("zeroPad", () => {
  const input = new Uint8Array([1, 2, 3]);
  const padded = zeroPad(input, 32); // Pad to 4 bytes
  expect(padded).toEqual(new Uint8Array([1, 2, 3, 0]));

  // No padding needed
  const aligned = new Uint8Array([1, 2, 3, 4]);
  expect(zeroPad(aligned, 32)).toEqual(aligned);
});

test("truncate", () => {
  const input = new Uint8Array([0xff, 0xff, 0xff]);
  expect(truncate(input, 16)).toEqual(new Uint8Array([0xff, 0xff]));
  expect(truncate(input, 12)).toEqual(new Uint8Array([0xff, 0x0f]));
});

test("tail", () => {
  const input = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
  expect(tail(input, 16)).toEqual(new Uint8Array([0x56, 0x78]));
});

test("ctEq", () => {
  const a = new Uint8Array([1, 2, 3]);
  const b = new Uint8Array([1, 2, 3]);
  const c = new Uint8Array([1, 2, 4]);

  expect(ctEq(a, b)).toBe(true);
  expect(ctEq(a, c)).toBe(false);
});

test("xor", () => {
  const a = new Uint8Array([0xff, 0x00, 0xaa]);
  const b = new Uint8Array([0x00, 0xff, 0x55]);
  const expected = new Uint8Array([0xff, 0xff, 0xff]);

  expect(xor(a, b)).toEqual(expected);
});
