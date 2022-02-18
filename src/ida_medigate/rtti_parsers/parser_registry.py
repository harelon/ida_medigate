class ParserRegistry:

    parsers=list()

    @classmethod
    def register_parser(cls, parser):
        cls.parsers.append(parser)

    @classmethod
    def get_fitting_parser(cls):
        for parser in cls.parsers:
            if parser.is_suitable():
                return parser
        return None