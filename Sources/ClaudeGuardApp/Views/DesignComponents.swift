import SwiftUI
import ClaudeGuardCore

public struct LiquidGlassCard<Content: View>: View {
    @Environment(\.appearsActive) private var appearsActive
    let tintColor: Color?
    let cornerRadius: CGFloat
    let paddingAmount: CGFloat
    @ViewBuilder let content: () -> Content

    public init(
        tint: Color? = nil,
        cornerRadius: CGFloat = 18,
        padding: CGFloat = 16,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.tintColor = tint
        self.cornerRadius = cornerRadius
        self.paddingAmount = padding
        self.content = content
    }

    public var body: some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        let glass: Glass = {
            if let tintColor {
                return Glass.regular.tint(tintColor.opacity(appearsActive ? 0.18 : 0.08))
            }
            return Glass.regular
        }()

        content()
            .padding(paddingAmount)
            .frame(maxWidth: .infinity, alignment: .leading)
            .glassEffect(glass, in: shape)
            .opacity(appearsActive ? 1.0 : 0.92)
    }
}

public enum SemanticBadgeTone {
    case safe
    case warning
    case danger
    case frozen
    case neutral

    public var color: Color {
        switch self {
        case .safe: return .green
        case .warning: return .orange
        case .danger: return .red
        case .frozen: return .cyan
        case .neutral: return .secondary
        }
    }
}

public struct StatusBadgePill: View {
    let text: String
    let tone: SemanticBadgeTone
    var systemImage: String? = nil

    public var body: some View {
        HStack(spacing: 4) {
            if let systemImage {
                Image(systemName: systemImage)
                    .font(.caption2.weight(.bold))
            }
            Text(text)
                .font(.caption.weight(.semibold))
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 3.5)
        .foregroundStyle(tone.color)
        .background(tone.color.opacity(0.15), in: Capsule())
        .overlay(Capsule().strokeBorder(tone.color.opacity(0.32), lineWidth: 0.8))
    }
}

public struct TrustScoreGaugeView: View {
    let score: Int?
    let purityLabel: String
    let isRestricted: Bool

    private var effectiveScore: Int {
        if isRestricted { return 0 }
        return max(0, min(100, score ?? 0))
    }

    private var scoreColor: Color {
        if isRestricted { return .red }
        guard let s = score else { return .secondary }
        switch s {
        case 80...: return .green
        case 50..<80: return .mint
        case 25..<50: return .orange
        default: return .red
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                if let score = isRestricted ? 0 : score {
                    Text("\(score)")
                        .font(.system(size: 36, weight: .bold, design: .rounded))
                        .foregroundStyle(scoreColor)
                    Text("/ 100")
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(.secondary)
                } else {
                    Text("—")
                        .font(.system(size: 34, weight: .bold, design: .rounded))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                StatusBadgePill(
                    text: purityLabel,
                    tone: isRestricted ? .danger : (score == nil ? .neutral : (effectiveScore >= 50 ? .safe : (effectiveScore >= 25 ? .warning : .danger)))
                )
            }

            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Capsule()
                        .fill(
                            LinearGradient(
                                colors: [.red.opacity(0.65), .orange.opacity(0.65), .yellow.opacity(0.65), .green.opacity(0.75)],
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                        .frame(height: 8)

                    if score != nil || isRestricted {
                        let xOffset = max(0, min(geo.size.width - 14, geo.size.width * CGFloat(effectiveScore) / 100.0 - 7))
                        Circle()
                            .fill(.white)
                            .frame(width: 14, height: 14)
                            .shadow(color: .black.opacity(0.35), radius: 2, y: 1)
                            .overlay(Circle().stroke(scoreColor, lineWidth: 3))
                            .offset(x: xOffset)
                    }
                }
            }
            .frame(height: 14)

            HStack {
                Text("0 高危")
                Spacer()
                Text("25")
                Spacer()
                Text("50 良好")
                Spacer()
                Text("80 纯净")
                Spacer()
                Text("100")
            }
            .font(.caption2)
            .foregroundStyle(.secondary)
        }
    }
}

public struct MetricRow: View {
    let label: String
    let value: String
    var badge: (String, SemanticBadgeTone)? = nil

    public var body: some View {
        HStack(spacing: 8) {
            Text(label)
                .font(.callout)
                .foregroundStyle(.secondary)
            Spacer(minLength: 8)
            if !value.isEmpty {
                Text(value)
                    .font(.callout.monospacedDigit())
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            if let badge {
                StatusBadgePill(text: badge.0, tone: badge.1)
            }
        }
        .padding(.vertical, 3)
    }
}
