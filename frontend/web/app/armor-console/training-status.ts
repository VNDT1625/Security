export type TrainingLifecycleStatus = 'idle' | 'training' | 'completed' | 'failed' | 'error';

export function shouldPollTraining(status: TrainingLifecycleStatus): boolean {
    return status === 'training';
}
