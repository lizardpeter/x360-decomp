#!/usr/bin/env python3
"""Translate an explicitly supplied XUI schema to the native reader's ordered input.
No schema or original firmware data is distributed by this project.
"""
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path

def compile_schema(root):
    descriptor=ET.parse(root/"17559.xhe").getroot()
    files=[x.text.strip() for x in descriptor.findall(".//RelationalExtension")]
    if not files or len(set(files))!=len(files):
        raise ValueError("invalid extension list")
    rows=[]
    classes=set()
    for name in files:
        if Path(name).name!=name or not name.endswith(".xml"):
            raise ValueError("invalid extension path")
        for cls in ET.parse(root/name).getroot().findall("XUIClass"):
            name=cls.attrib["Name"]
            base=cls.attrib["BaseClassName"]
            if name in classes:
                raise ValueError("duplicate class: "+name)
            classes.add(name)
            rows.append("C "+name+" "+("-" if base=="(null)" else base))
            for p in cls.findall("PropDef"):
                flags=p.attrib.get("Flags","").split("|")
                rows.append("P "+p.attrib["Name"]+" "+p.attrib["Type"]+" "+str(int("indexed" in flags)))
    return "\n".join(rows)+"\n"

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("schema_root",type=Path)
    p.add_argument("output",type=Path)
    args=p.parse_args()
    args.output.write_text(compile_schema(args.schema_root),encoding="utf-8")

if __name__=="__main__":main()
