import { describe, expect, it } from 'vitest';
import { shouldPollTraining } from './training-status';

describe('shouldPollTraining', () => {
    it('continues only while the backend reports an active training job', () => {
        expect(shouldPollTraining('training')).toBe(true);
        expect(shouldPollTraining('completed')).toBe(false);
        expect(shouldPollTraining('failed')).toBe(false);
        expect(shouldPollTraining('error')).toBe(false);
        expect(shouldPollTraining('idle')).toBe(false);
    });
});
