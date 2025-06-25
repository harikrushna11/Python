import React from "react";
import { HistoryState } from "../../shared/types/home";
import { formatDate, formatTime } from "../../shared/data/Description";
import "./History.css";
import ThemedSkeleton from "../skeleton/ThemedSkeleton";
import Skeleton from "react-loading-skeleton";
import {
  useGetPrHistoryQuery,
  useLazyGetPrAnalysisByIdQuery,
} from "../../api/prHistoryApiSlice";
import { useSelector } from "react-redux";
import { selectUser } from "../../shared/slices/userSlice";
import { fetchPRHistoryByIdWithLogging } from "../../shared/services/historyService";
import { postMessage } from "../../shared/vscode/vscode-api";

interface HistoryProps {
  history: HistoryState;
  handleHistoryItemClick: (
    id: number,
    fileName: string,
    factor: string
  ) => void;
  refetchHistory: any;
}

const History: React.FC<HistoryProps> = ({
  history,
  handleHistoryItemClick,
  refetchHistory,
}) => {
  const { list, loading, error: historyError } = history;
  const { userId } = useSelector(selectUser);
  const [loadingItemId, setLoadingItemId] = React.useState<number | null>(null);
  const [manualLoading, setManualLoading] = React.useState(false);

  const {
    data: prHistoryData,
    isLoading: prLoading,
    refetch: refetcPrhHistory,
  } = useGetPrHistoryQuery(userId);

  const [getPRHistoryByIdTrigger] = useLazyGetPrAnalysisByIdQuery();

  const [showEditorHistory, setShowEditorHistory] = React.useState(true);
  const [showPrHistory, setShowPrHistory] = React.useState(true);

  const handlePRHistoryItemClick = async (analysisid: number) => {
    try {
      setLoadingItemId(analysisid);
      const res = await fetchPRHistoryByIdWithLogging({
        getPRHistoryByIdTrigger,
        userId,
        analysisId: analysisid,
      });
      const combined = `${res.pr_number}-${res.repo_name}`;
      postMessage({
        command: "openMarkdown",
        name: combined,
        text: res.analysis,
      });
    } catch (error: any) {
      postMessage({
        command: "showNotification",
        text: "Failed to fetch PR history, Please try again opening it.",
        error: true,
      });
    } finally {
      setLoadingItemId(null);
    }
  };

  const refreshHistory = async () => {
    try {
      setManualLoading(true);
      await Promise.all([refetchHistory(), refetcPrhHistory()]);
    } finally {
      setManualLoading(false);
    }
  };

  return (
    <div
      className={`flex flex-col absolute top-12 z-0 h-[90vh] w-full justify-start ${
        loading || manualLoading || prLoading
          ? "overflow-hidden"
          : "overflow-y-auto"
      }`}
    >
      <div className="flex items-center justify-between px-2  pb-2">
        <h2 className="text-[14px] font-semibold text-[var(--vscode-editor-foreground)]">
         
        </h2>
        <button
          onClick={refreshHistory}
          className="text-[12px] text-[var(--vscode-button-foreground)] bg-[var(--vscode-button-background)] hover:bg-[var(--vscode-button-hoverBackground)] px-3 py-1 rounded-md transition-colors"
        >
          Sync History
        </button>
      </div>

      <div className="p-2 font-bold text-[13px] text-left w-full flex flex-col gap-2">
        {/* Code Editor's History */}
        <div
          className="flex items-center justify-between text-[14px] text-[var(--vscode-editor-foreground)] font-semibold cursor-pointer"
          onClick={() => setShowEditorHistory(!showEditorHistory)}
        >
          <span>Code Editor's History</span>
          <button>
            <svg
              className={`-mr-1 h-5 w-5 text-[var(--vscode-editor-sidebar)] transform ${
                !showEditorHistory ? "" : "rotate-180"
              }`}
              viewBox="0 0 20 20"
              fill="currentColor"
              aria-hidden="true"
            >
              <path
                fillRule="evenodd"
                d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z"
                clipRule="evenodd"
              />
            </svg>
          </button>
        </div>

        {showEditorHistory && (
          <>
            {loading || manualLoading ? (
              <ThemedSkeleton>
                {Array(3)
                  .fill(null)
                  .map((_, index) => (
                    <div
                      key={index}
                      className="flex dark:bg-opacity-20"
                      style={{ height: "80px" }}
                    >
                      <div className="px-2 md:px-4 py-1 text-lg w-full">
                        <Skeleton height={50} />
                      </div>
                    </div>
                  ))}
              </ThemedSkeleton>
            ) : !historyError && list.length > 0 ? (
              list.map((item) => (
                <div
                  key={item.id}
                  className="rounded-md bg-[var(--vscode-editor-background)] p-3 text-left cursor-pointer"
                  onClick={() =>
                    handleHistoryItemClick(item.id, item.file_name, item.factor)
                  }
                >
                  <label className="flex-col cursor-pointer text-start flex gap-0 item-start text-[var(--vscode-editor-foreground)] text-lg font-[400]">
                    <div className="flex items-center justify-between">
                      <span className="text-[13px] truncate-text">
                        {item.file_name}
                      </span>
                      <span className="ml-2 text-[13px] truncate-text">
                        {item.factor === "power_analysis"
                          ? "Power Analysis"
                          : item.factor === "owasp"
                          ? "OWASP TOP 10"
                          : item.factor.charAt(0).toUpperCase() +
                            item.factor.slice(1)}
                      </span>
                    </div>
                    <div className="font-bold text-left text-[13px] flex justify-between">
                      <span>{formatDate(item.created_at)}</span>
                      <span>{formatTime(item.created_at)}</span>
                    </div>
                  </label>
                </div>
              ))
            ) : historyError ? (
              <div className="text-[var(--vscode-editor-foreground)]">
                Failed to fetch history! We are working on it.
              </div>
            ) : null}
          </>
        )}

        {/* PR Review's History */}
        {prHistoryData?.analysis_history?.length > 0 && (
          <>
            <div
              className="flex items-center justify-between text-[14px] text-[var(--vscode-editor-foreground)] font-semibold mt-5 cursor-pointer"
              onClick={() => setShowPrHistory(!showPrHistory)}
            >
              <span>PR Review's History</span>
              <button>
                <svg
                  className={`-mr-1 h-5 w-5 text-[var(--vscode-editor-sidebar)] transform ${
                    !showPrHistory ? "" : "rotate-180"
                  }`}
                  viewBox="0 0 20 20"
                  fill="currentColor"
                  aria-hidden="true"
                >
                  <path
                    fillRule="evenodd"
                    d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z"
                    clipRule="evenodd"
                  />
                </svg>
              </button>
            </div>

            {showPrHistory && (
              <>
                {prLoading || manualLoading ? (
                  <ThemedSkeleton>
                    {Array(3)
                      .fill(null)
                      .map((_, index) => (
                        <div
                          key={index}
                          className="flex dark:bg-opacity-20"
                          style={{ height: "80px" }}
                        >
                          <div className="px-2 md:px-4 py-1 text-lg w-full">
                            <Skeleton height={50} />
                          </div>
                        </div>
                      ))}
                  </ThemedSkeleton>
                ) : (
                  prHistoryData.analysis_history.map((item: any) => (
                    <div
                      key={item.id}
                      className="rounded-md bg-[var(--vscode-editor-background)] p-3 text-left cursor-pointer min-h-[90px]"
                      onClick={() => handlePRHistoryItemClick(item.id)}
                    >
                      {loadingItemId === item.id ? (
                        <div className="text-[13px] text-[var(--vscode-editor-foreground)]">
                          Loading...
                        </div>
                      ) : (
                        <label className="flex-col cursor-pointer text-start flex gap-1 item-start text-[var(--vscode-editor-foreground)] text-lg font-[400]">
                          <div className="flex items-center justify-between w-full">
                            <span className="text-[12px] font-semibold">
                              PR Number:
                            </span>
                            <span className="text-[13px] truncate-text ml-1">
                              {item.pr_number || "Untitled"}
                            </span>
                            <span className="text-[13px] truncate-text ml-auto">
                              {item.factor === "power_analysis"
                                ? "Power Analysis"
                                : item.factor.charAt(0).toUpperCase() +
                                  item.factor.slice(1)}
                            </span>
                          </div>
                          <div className="flex items-center justify-between w-full text-[13px]">
                            <span className="truncate-text">
                              {item.repo_name || "Unknown Repository"}
                            </span>
                            <span>
                              {formatDate(item.created_at)} •{" "}
                              {formatTime(item.created_at)}
                            </span>
                          </div>
                        </label>
                      )}
                    </div>
                  ))
                )}
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default History;
