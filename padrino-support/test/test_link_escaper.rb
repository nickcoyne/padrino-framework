# coding: utf-8
describe "LinkEscaper" do
  examples = [
    [ #0
      "htЫtp://usЫer:passoЫd@exaЫmple.com:8080/path ПУТЬ?queЫry=valЫue#fragmeЫnt",
      "ht%D0%ABtp://usЫer:passoЫd@exaЫmple.com:8080/path%20ПУТЬ?queЫry=valЫue#fragmeЫnt",
    ],
    [ #1
      "/a Ы",
      "/a%20Ы",
    ],
    [ #2
      "mailto:jane doe@does.com",
      "mailto:jane%20doe@does.com",
    ],
    [ #3
      "already%20encoded",
      "already%20encoded",
    ],
    [ #4
      "half%20 encoded?q=%26%3d%2fp",
      "half%20%20encoded?q=%26%3d%2fp",
    ],
    [ #5
      " spaced link ",
      "spaced%20link",
    ],
    [ #7
      "http://a?:b$#@e.f/p ?q=6#8",
      "http://a?:b$#@e.f/p%20?q=6#8",
    ],
  ]
  SIMPLE_VIOLATIONS = [0]

  describe "IRI link escaper" do
    before do
      Padrino::Utils::LinkEscaper.engine = Padrino::Utils::LinkEscaper::IRI.new
    end
    examples.each do |source, expected|
      it "should properly escape #{source}" do
        actual = Padrino::Utils.escape_link(source)
        assert_equal expected, actual
      end
    end
  end

  describe "Simple link escaper" do
    before do
      Padrino::Utils::LinkEscaper.engine = Padrino::Utils::LinkEscaper::Simple.new
    end
    examples.each_with_index do |(source, expected), index|
      it "should properly escape #{source}" do
        skip if SIMPLE_VIOLATIONS.include?(index)
        actual = Padrino::Utils.escape_link(source)
        assert_equal expected, actual
      end
    end
  end
end
