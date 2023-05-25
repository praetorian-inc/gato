
# def test_print_runners(capfd):

#     gh_enumeration_runner = Enumerator(
#         "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
#         socks_proxy=None,
#         http_proxy=None,
#         skip_clones=False,
#         output_yaml=False,
#         skip_log=False,
#     )

#     runners_json = """
#     {
#     "total_count":1,
#     "runners":[
#         {
#             "id":21,
#             "name":"ghrunner-test",
#             "os":"Linux",
#             "status":"online",
#             "busy":false,
#             "labels":[
#                 {
#                 "id":1,
#                 "name":"self-hosted",
#                 "type":"read-only"
#                 },
#                 {
#                 "id":2,
#                 "name":"Linux",
#                 "type":"read-only"
#                 },
#                 {
#                 "id":3,
#                 "name":"X64",
#                 "type":"read-only"
#                 }
#             ]
#         }
#     ]
#     }
#     """

#     gh_enumeration_runner._Enumerator__print_runner_info(
#         json.loads(runners_json)
#     )

#     out, err = capfd.readouterr()

#     assert "The runner has the following labels: self-hosted, Linux, X64" in \
#         escape_ansi(out)