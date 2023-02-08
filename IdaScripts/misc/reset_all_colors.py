import idautils
import idc

# resets highlights to theme default colors (when you use someone elses idb with mismatched highlights for example)
heads = idautils.Heads(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA))
funcCalls = []
for i in heads:
	idc.set_color(i, idc.CIC_ITEM, idc.DEFCOLOR)