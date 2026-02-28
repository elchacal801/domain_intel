/**
 * MarkdownText — renders markdown content with proper styling.
 * Also strips em-dashes (—) → regular dashes (-) before rendering.
 *
 * Uses react-markdown for parsing.
 */
import ReactMarkdown from 'react-markdown';

function sanitizeText(text) {
    if (!text) return '';
    return text
        .replace(/\u2014/g, '-')    // em-dash → hyphen
        .replace(/\u2013/g, '-')    // en-dash → hyphen
        .replace(/\u2018/g, "'")    // left single quote
        .replace(/\u2019/g, "'")    // right single quote
        .replace(/\u201C/g, '"')    // left double quote
        .replace(/\u201D/g, '"');   // right double quote
}

export default function MarkdownText({ children, className = '' }) {
    const sanitized = sanitizeText(children);

    return (
        <div className={`markdown-text ${className}`}>
            <ReactMarkdown
                components={{
                    h1: ({ children }) => <h1 className="text-base font-bold text-text-primary mb-2 mt-3">{children}</h1>,
                    h2: ({ children }) => <h2 className="text-sm font-bold text-text-primary mb-1.5 mt-2.5">{children}</h2>,
                    h3: ({ children }) => <h3 className="text-xs font-bold text-text-primary mb-1 mt-2">{children}</h3>,
                    p: ({ children }) => <p className="text-xs leading-relaxed text-text-secondary mb-2">{children}</p>,
                    ul: ({ children }) => <ul className="list-disc pl-4 space-y-1 mb-2">{children}</ul>,
                    ol: ({ children }) => <ol className="list-decimal pl-4 space-y-1 mb-2">{children}</ol>,
                    li: ({ children }) => <li className="text-xs leading-relaxed text-text-secondary">{children}</li>,
                    strong: ({ children }) => <strong className="font-semibold text-text-primary">{children}</strong>,
                    em: ({ children }) => <em className="italic text-text-secondary">{children}</em>,
                    code: ({ children }) => <code className="font-mono text-[11px] bg-white/5 rounded px-1 py-0.5 text-text-primary">{children}</code>,
                    blockquote: ({ children }) => <blockquote className="border-l-2 border-white/10 pl-3 my-2 text-text-muted">{children}</blockquote>,
                    hr: () => <hr className="border-border-subtle my-3" />,
                    a: ({ href, children }) => <a href={href} className="text-blue-400 hover:underline" target="_blank" rel="noopener noreferrer">{children}</a>,
                }}
            >
                {sanitized}
            </ReactMarkdown>
        </div>
    );
}
