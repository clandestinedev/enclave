import { describe, expect, it } from 'vitest';

import { WIRE_VERSION } from '../src/version';

describe('wire contracts', () => {
  it('defines a stable wire protocol version', () => {
    expect(WIRE_VERSION).toBe(1);
  });
});
