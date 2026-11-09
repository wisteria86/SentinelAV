# Purpose: Create a process response plan or explicitly apply approved hashes. No auto mode.
# Works with: data.storage, paths, response.containment, response.response, updates.artifacts
# Used by: the Python module loader or CLI entry point

"""Create a process response plan or explicitly apply approved hashes. No auto mode."""
import argparse
import json
from pathlib import Path
from sentinelav.data.storage import Store
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.response.containment import plan_tree,execute_plan
from sentinelav.response.response import ResponseService
from sentinelav.updates.artifacts import bounded_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    plan=sub.add_parser('plan')
    plan.add_argument('pid',type=int); plan.add_argument('--creation',required=True,type=float)
    plan.add_argument('--output',required=True,type=Path)
    apply=sub.add_parser('apply')
    apply.add_argument('plan'); apply.add_argument('--database',required=True,type=Path)
    apply.add_argument('--approve-hash',required=True,action='append')
    args=parser.parse_args()
    if args.command=='plan':
        result=plan_tree(args.pid,args.creation)
        with args.output.open('x',encoding='utf-8') as stream: json.dump(result,stream,indent=2)
    else:
        store=Store(args.database)
        try: print(json.dumps(execute_plan(ResponseService(store,RESOURCE_ROOT),bounded_json(args.plan,65536),args.approve_hash),indent=2))
        finally: store.db.close()


if __name__=='__main__': main()
