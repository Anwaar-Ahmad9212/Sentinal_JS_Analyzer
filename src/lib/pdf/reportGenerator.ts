import { jsPDF } from 'jspdf';
import { AnalysisReport, RiskLevel, SecurityIssue } from '../analyzer/types';

// Helper to manage page breaks
const checkPageBreak = (doc: jsPDF, y: number, heightNeeded: number = 10) => {
    const pageHeight = doc.internal.pageSize.getHeight();
    if (y + heightNeeded > pageHeight - 20) {
        doc.addPage();
        return 20; // Reset Y to top margin
    }
    return y;
};

export const generateNativePDFReport = (report: AnalysisReport, sourceCode: string) => {
    const doc = new jsPDF('p', 'mm', 'a4');
    const margin = 20;
    const pageWidth = doc.internal.pageSize.getWidth();
    const maxWidth = pageWidth - margin * 2;
    let yPos = 20;

    // --- TITLE HEADER ---
    doc.setFont("helvetica", "bold");
    doc.setFontSize(28);
    doc.setTextColor(30, 58, 138); // Deep Blue
    doc.text("VULN GUARD", margin, yPos);
    yPos += 10;
    
    doc.setFont("helvetica", "normal");
    doc.setFontSize(14);
    doc.setTextColor(100, 116, 139); // Slate
    doc.text("Security Intelligence & Audit Report", margin, yPos);
    yPos += 15;

    // Divider
    doc.setDrawColor(226, 232, 240);
    doc.line(margin, yPos, pageWidth - margin, yPos);
    yPos += 15;

    // --- EXECUTIVE SUMMARY ---
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.setTextColor(15, 23, 42);
    doc.text("Executive Summary", margin, yPos);
    yPos += 10;

    doc.setFontSize(11);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(71, 85, 105);
    const date = new Date().toLocaleString();
    doc.text(`Report Generated : ${date}`, margin, yPos);
    yPos += 8;
    
    // Status colors
    const scoreColor = report.stats.score >= 80 ? [22, 163, 74] : report.stats.score >= 50 ? [202, 138, 4] : [220, 38, 38];
    doc.text(`Security Score   : `, margin, yPos);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(scoreColor[0], scoreColor[1], scoreColor[2]);
    doc.text(`${report.stats.score}%`, margin + 35, yPos);
    
    doc.setFont("helvetica", "normal");
    doc.setTextColor(71, 85, 105);
    yPos += 8;
    doc.text(`Total Issues     : ${report.stats.total}`, margin, yPos);
    yPos += 8;
    doc.text(`Critical Issues  : `, margin, yPos);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(report.stats.critical > 0 ? 220 : 71, report.stats.critical > 0 ? 38 : 85, report.stats.critical > 0 ? 38 : 105);
    doc.text(`${report.stats.critical}`, margin + 35, yPos);
    yPos += 15;

    // Divider
    doc.setDrawColor(226, 232, 240);
    doc.line(margin, yPos, pageWidth - margin, yPos);
    yPos += 15;

    // --- ANALYZED SOURCE CODE ---
    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.setTextColor(15, 23, 42);
    doc.text("Analyzed Source Code", margin, yPos);
    yPos += 10;

    doc.setFont("courier", "normal");
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);

    const sourceLines = doc.splitTextToSize(sourceCode, maxWidth);
    
    sourceLines.forEach((line: string) => {
        yPos = checkPageBreak(doc, yPos, 5);
        doc.text(line, margin, yPos);
        yPos += 4;
    });
    
    yPos += 10;

    // Divider
    doc.setDrawColor(226, 232, 240);
    doc.line(margin, yPos, pageWidth - margin, yPos);
    yPos += 15;

    // --- DETAILED FINDINGS ---
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.setTextColor(15, 23, 42);
    doc.text("Detailed Security Findings", margin, yPos);
    yPos += 15;

    if (report.issues.length === 0) {
        doc.setFontSize(12);
        doc.setFont("helvetica", "bold");
        doc.setTextColor(16, 185, 129); // Emerald
        doc.text("System Secure: Zero vulnerabilities detected in the analyzed scope.", margin, yPos);
    } else {
        report.issues.forEach((issue, index) => {
            yPos = checkPageBreak(doc, yPos, 40);

            // 1. Issue Title
            doc.setFont("helvetica", "bold");
            doc.setFontSize(13);
            
            if (issue.risk === RiskLevel.CRITICAL) doc.setTextColor(220, 38, 38);
            else if (issue.risk === RiskLevel.HIGH) doc.setTextColor(234, 88, 12);
            else if (issue.risk === RiskLevel.MEDIUM) doc.setTextColor(202, 138, 4);
            else doc.setTextColor(37, 99, 235);
            
            doc.text(`${index + 1}. [${issue.risk}] ${issue.type} Vulnerability`, margin, yPos);
            yPos += 6;

            // 2. Location
            doc.setFontSize(10);
            doc.setFont("helvetica", "normal");
            doc.setTextColor(100, 116, 139);
            doc.text(`Location: ${issue.location}`, margin, yPos);
            yPos += 8;

            // 3. Message
            doc.setTextColor(15, 23, 42);
            doc.setFont("helvetica", "bold");
            doc.text("Description:", margin, yPos);
            doc.setFont("helvetica", "normal");
            const msgLines = doc.splitTextToSize(issue.message, maxWidth - 25);
            doc.text(msgLines, margin + 25, yPos);
            yPos += (msgLines.length * 5) + 3;

            // 4. Explanation
            doc.setFont("helvetica", "bold");
            doc.text("Impact:", margin, yPos);
            doc.setFont("helvetica", "normal");
            const expLines = doc.splitTextToSize(issue.explanation, maxWidth - 25);
            doc.text(expLines, margin + 25, yPos);
            yPos += (expLines.length * 5) + 3;

            // 5. Taint Flow (if exists)
            if (issue.flow && issue.flow.length > 0) {
                yPos = checkPageBreak(doc, yPos, 20);
                doc.setFont("helvetica", "bold");
                doc.text("Taint Path:", margin, yPos);
                doc.setFont("courier", "normal");
                doc.setFontSize(9);
                doc.setTextColor(234, 88, 12); // Orange for taint
                
                const flowText = issue.flow.join(' -> ');
                const flowLines = doc.splitTextToSize(flowText, maxWidth - 25);
                doc.text(flowLines, margin + 25, yPos);
                yPos += (flowLines.length * 4) + 4;
            }

            // 6. Fix Code Snippet
            yPos = checkPageBreak(doc, yPos, 30);
            doc.setFont("helvetica", "bold");
            doc.setFontSize(10);
            doc.setTextColor(15, 23, 42);
            doc.text("Remediation Code:", margin, yPos);
            yPos += 5;

            doc.setFont("courier", "normal");
            doc.setFontSize(9);
            doc.setTextColor(22, 163, 74); // Green
            
            const fixLines = doc.splitTextToSize(issue.fix_code, maxWidth - 6);
            const boxHeight = (fixLines.length * 4) + 6;
            
            yPos = checkPageBreak(doc, yPos, boxHeight + 10);
            
            // Draw gray box for code
            doc.setFillColor(248, 250, 252);
            doc.setDrawColor(203, 213, 225);
            doc.rect(margin, yPos, maxWidth, boxHeight, 'FD');
            
            doc.text(fixLines, margin + 3, yPos + 6);
            yPos += boxHeight + 10;
            
            // Issue Divider
            if (index < report.issues.length - 1) {
                doc.setDrawColor(241, 245, 249); // Lighter line
                doc.line(margin + 10, yPos, pageWidth - margin - 10, yPos);
                yPos += 10;
            }
        });
    }

    doc.save("VulnGuard_Security_Report.pdf");
};
