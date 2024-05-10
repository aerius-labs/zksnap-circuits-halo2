"use client";

import React, { useState, useEffect } from "react";

export default function Home() {
    const [isRunning, setIsRunning] = useState(false);
    const [worker, setWorker] = useState(null);

    useEffect(() => {
        const newWorker = new Worker(new URL("./worker.js", import.meta.url), {
            type: "module",
        });
        newWorker.onmessage = (e) => {
            if (e.data.status === "success") {
                console.log(e.data.message);
                setIsRunning(false);
            } else if (e.data.status === "error") {
                console.error(e.data.message);
                setIsRunning(false);
            }
        };
        setWorker(newWorker);

        // Cleanup function to terminate the worker when the component unmounts
        return () => newWorker.terminate();
    }, []);

    const runMain = () => {
        setIsRunning(true);
        worker.postMessage({ action: "runMain" });
    };

    return (
        <main>
            <h1>Hello, World!</h1>
            <button onClick={runMain} disabled={isRunning}>
                {isRunning ? "Running..." : "Run Main"}
            </button>
        </main>
    );
}
