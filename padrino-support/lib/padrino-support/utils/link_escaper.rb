module Padrino
  module Utils
    module LinkEscaper
      def self.engine=(escaper)
        @engine = escaper
      end

      def self.engine
        @engine ||= IRI.new
      end

      class Simple
        def escape(link)
          link.strip.gsub(' ', '%20')
        end
      end

      class IRI
        UCSCHAR = Regexp.compile(<<-EOS.gsub(/\s+/, ''))
          [\\u00A0-\\uD7FF]|[\\uF900-\\uFDCF]|[\\uFDF0-\\uFFEF]|
          [\\u{10000}-\\u{1FFFD}]|[\\u{20000}-\\u{2FFFD}]|[\\u{30000}-\\u{3FFFD}]|
          [\\u{40000}-\\u{4FFFD}]|[\\u{50000}-\\u{5FFFD}]|[\\u{60000}-\\u{6FFFD}]|
          [\\u{70000}-\\u{7FFFD}]|[\\u{80000}-\\u{8FFFD}]|[\\u{90000}-\\u{9FFFD}]|
          [\\u{A0000}-\\u{AFFFD}]|[\\u{B0000}-\\u{BFFFD}]|[\\u{C0000}-\\u{CFFFD}]|
          [\\u{D0000}-\\u{DFFFD}]|[\\u{E1000}-\\u{EFFFD}]
        EOS
        IUNRESERVED = Regexp.compile("[A-Za-z0-9\._~-]|#{UCSCHAR}").freeze
        PCT_ENCODED = Regexp.compile("%[0-9A-Fa-f][0-9A-Fa-f]").freeze
        SUB_DELIMS = Regexp.compile("[!\\$&'\\(\\)\\*\\+,;=]").freeze

        IP_literal = Regexp.compile("\\[[0-9A-Fa-f:\\.]*\\]").freeze
        IREG_NAME   = Regexp.compile("(?:(?:#{IUNRESERVED})|(?:#{PCT_ENCODED})|(?:#{SUB_DELIMS}))*").freeze

        IUSERINFO = Regexp.compile("(?:(?:#{IUNRESERVED})|(?:#{PCT_ENCODED})|(?:#{SUB_DELIMS})|:)*").freeze
        IHOST = Regexp.compile("(?:#{IP_literal})|(?:#{IREG_NAME})").freeze
        PORT = Regexp.compile("[0-9]*").freeze

        IPCHAR = Regexp.compile("(?:#{IUNRESERVED}|#{PCT_ENCODED}|#{SUB_DELIMS}|:|@)").freeze
        IPRIVATE = Regexp.compile("[\\uE000-\\uF8FF]|[\\u{F0000}-\\u{FFFFD}]|[\\u100000-\\u10FFFD]").freeze

        ISEGMENT = Regexp.compile("(?:#{IPCHAR})*").freeze
        ISEGMENT_NZ = Regexp.compile("(?:#{IPCHAR})+").freeze

        IPATH_ABEMPTY = Regexp.compile("(?:/#{ISEGMENT})*").freeze
        IPATH_ABSOLUTE = Regexp.compile("/(?:(?:#{ISEGMENT_NZ})(/#{ISEGMENT})*)?").freeze
        IPATH_ROOTLESS = Regexp.compile("(?:#{ISEGMENT_NZ})(?:/#{ISEGMENT})*").freeze
        IPATH_EMPTY = Regexp.compile("").freeze

        SCHEME = Regexp.compile("[A-za-z](?:[A-Za-z0-9+-\.])*").freeze
        IAUTHORITY = Regexp.compile("(?:#{IUSERINFO}@)?#{IHOST}(?::#{PORT})?").freeze
        IQUERY = Regexp.compile("(?:#{IPCHAR}|#{IPRIVATE}|/|\\?)*").freeze
        IFRAGMENT = Regexp.compile("(?:#{IPCHAR}|/|\\?)*").freeze
        IHIER_PART = Regexp.compile("(?:(?://#{IAUTHORITY}#{IPATH_ABEMPTY})|(?:#{IPATH_ABSOLUTE})|(?:#{IPATH_ROOTLESS})|(?:#{IPATH_EMPTY}))").freeze

        SEGMENT_SYNTAX = [SCHEME, IAUTHORITY, IHIER_PART, IQUERY, IFRAGMENT].freeze
        SEGMENT_VIOLATION = SEGMENT_SYNTAX.map{ |syntax| /[^(?:#{syntax})]/.freeze }.freeze
        SEGMENT_PREPEND = ['', '//', '', '?', '#'].map(&:freeze).freeze
        SEGMENT_APPEND = [':', '', '', '', ''].map(&:freeze).freeze

        IRI_SEGMENTS = /^(?:([^:\/?#]+):)?(?:\/\/([^\/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/.freeze

        def escape(link)
          return link if link.html_safe?
          _, *segments = link.strip.match(IRI_SEGMENTS).to_a
          result = String.new
          segments.each_with_index do |segment, index|
            if segment
              result <<
                SEGMENT_PREPEND[index] <<
                escape_segment(segment, SEGMENT_VIOLATION[index]) <<
                SEGMENT_APPEND[index]
            end
          end
          result
        end

        private

        def escape_segment(segment, violation)
          segment.gsub(violation) do |part|
            encoded_part = String.new
            part.each_byte do |byte|
              encoded_part << sprintf('%%%02X', byte)
            end
            encoded_part
          end
        end
      end
    end
  end
end
