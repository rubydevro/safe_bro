module SafeBro
  module ApplicationHelper
    PER_PAGE = 50

    REVIEW_LABELS = { "pending" => "Pending", "approved" => "Appropriate", "flagged" => "Flagged" }.freeze
    REVIEW_TONES = { "pending" => "muted", "approved" => "green", "flagged" => "red" }.freeze

    def safe_bro_time(time)
      return "-" unless time

      content_tag(:time, time.utc.strftime("%Y-%m-%d %H:%M"), datetime: time.iso8601, title: time.utc.to_s)
    end

    def safe_bro_duration(seconds)
      return "#{seconds}s" if seconds < 60
      return "#{seconds / 60}m" if seconds < 3600

      "#{seconds / 3600}h #{seconds % 3600 / 60}m"
    end

    def safe_bro_review_label(status)
      REVIEW_LABELS.fetch(status.to_s, status.to_s.capitalize)
    end

    def safe_bro_review_tone(status)
      REVIEW_TONES.fetch(status.to_s, "muted")
    end

    # Coloured review status, as text.
    def review_status_text(status)
      content_tag(:span, safe_bro_review_label(status), class: "bh-status bh-tone-#{safe_bro_review_tone(status)}")
    end

    def command_flag(command)
      case command.status
      when "blocked" then content_tag(:span, "Blocked", class: "bh-flag")
      when "suspicious" then content_tag(:span, "Flagged", class: "bh-flag")
      end
    end

    def safe_bro_count(count, singular, plural = singular.pluralize)
      "#{count} #{count == 1 ? singular : plural}"
    end

    # "← Newer / Older →" for pages of PER_PAGE rows. `page` counts from 0.
    def safe_bro_pager(total:, page:, noun:)
      newer = link_to("← Newer", url_for(request.query_parameters.merge(page: page - 1))) if page > 0
      older = link_to("Older →", url_for(request.query_parameters.merge(page: page + 1))) if (page + 1) * PER_PAGE < total
      content_tag(:div, class: "bh-meta", style: "display:flex;justify-content:space-between;gap:16px;margin-top:14px") do
        safe_join([ content_tag(:span, safe_bro_count(total, noun)), content_tag(:span, safe_join([ newer, older ].compact, " ")) ])
      end
    end

    # Short, readable text for a list of config values (never raw secrets: callers pass patterns and names).
    def safe_bro_rule(value)
      value.respond_to?(:source) ? value.inspect : value.to_s
    end
  end
end
