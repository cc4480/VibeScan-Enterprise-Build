import { customFetch } from "@workspace/api-client-react";

export interface SubmitFeedbackInput {
  message: string;
  rating?: number;
  context?: string;
}

export async function submitFeedback(input: SubmitFeedbackInput): Promise<void> {
  await customFetch<{ recorded: boolean }>("/api/feedback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}
