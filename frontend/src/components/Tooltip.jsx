import { useState } from 'react';

/**
 * Lightweight hover tooltip. Wrap any element to show a tooltip on hover.
 *
 * Usage: <Tooltip text="Explanation…"><span>hover me</span></Tooltip>
 */
export default function Tooltip({ text, children, className = '' }) {
    const [show, setShow] = useState(false);

    if (!text) return children;

    return (
        <span
            className={`tooltip-trigger inline-flex ${className}`}
            onMouseEnter={() => setShow(true)}
            onMouseLeave={() => setShow(false)}
        >
            {children}
            {show && <span className="tooltip-content">{text}</span>}
        </span>
    );
}
