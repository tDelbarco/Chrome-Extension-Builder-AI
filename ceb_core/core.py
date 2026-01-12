from collections import Counter
import hashlib
from bs4 import BeautifulSoup
from bs4 import Tag

#c=========================
def parse_html(content: bytes | str):
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="ignore")
    return BeautifulSoup(content, "html.parser")

# =========================
# Constantes y utilidades
# =========================

MAX_DEPTH = 12

IGNORED_TAGS = {
    "script", "style", "link", "meta", "svg", "noscript"
}

SEMANTIC_TAGS = {
    "article", "section", "li", "p", "a",
    "img", "h1", "h2", "h3", "h4",
    "ul", "ol", "figure"
}

DOMINANCE_THRESHOLD = 0.6


def normalize_classes(tag):
    return tuple(sorted(tag.get("class", [])))


def structural_fingerprint(tag, depth):
    if depth > MAX_DEPTH:
        return None
    if not tag.name or tag.name in IGNORED_TAGS:
        return None

    return (
        tag.name,
        normalize_classes(tag),
        depth
    )


def children_fingerprints(tag, depth):
    fps = []
    for child in tag.children:
        if getattr(child, "name", None):
            fp = structural_fingerprint(child, depth + 1)
            if fp:
                fps.append(fp)
    return Counter(fps)


def signature_id(signature):
    return hashlib.sha1(str(signature).encode()).hexdigest()[:8]


def build_css_selector(tag, classes):
    if classes:
        return tag + "." + ".".join(classes)
    return tag


# =========================
# Funciones de detección de variables
# =========================
IGNORED_ATTRIBUTES = {"class", "id", "style", "role"}

def extract_value_candidates(item_node, max_depth=3, min_text_length=15):
    candidates = []
    def walk(node, depth, path):
        if depth > max_depth or not isinstance(node, Tag):
            return

        # Texto
        text = node.get_text(strip=True)
        if text and len(text) >= min_text_length:
            candidates.append({"path": path, "type": "text", "node": node})

        # Atributos
        for attr, value in node.attrs.items():
            if attr in IGNORED_ATTRIBUTES or not value:
                continue
            candidates.append({
                "path": path, "type": "attribute", "attribute": attr, "node": node
            })

        # Inputs
        if node.name in {"input", "textarea", "select"}:
            candidates.append({
                "path": path, "type": "input", "attribute": "value", "node": node
            })

        # Descenso (Usando tu lógica de clases en el path)
        for child in node.children:
            if isinstance(child, Tag):
                classes = child.get("class", [])
                c_str = "." + ".".join(sorted(classes)) if classes else ""
                child_path = f"{path} > {child.name}{c_str}"
                walk(child, depth + 1, child_path)

    walk(item_node, 0, ".")
    return candidates

def _read_value(candidate):
    node, vtype = candidate["node"], candidate["type"]
    attr = candidate.get("attribute")
    if vtype == "text": return node.get_text(strip=True)
    if vtype in {"attribute", "input"}: return node.get(attr)
    return None

def _detect_in_repetitive_group(items, max_depth, min_text_length):
    buckets = {}
    for item in items:
        candidates = extract_value_candidates(item, max_depth, min_text_length)
        for c in candidates:
            key = (c["path"], c["type"], c.get("attribute"))
            buckets.setdefault(key, []).append(_read_value(c))
    
    results = []
    for (path, vtype, attr), values in buckets.items():
        unique = {v for v in values if v is not None}
        if len(unique) > 1:
            results.append({
                "path": path, 
                "type": vtype, 
                "attribute": attr, 
                "variation": "intra-items"
            })
    return results

# =========================
# Clase principal
# =========================

class DOMAnalyzer:
    def __init__(self, soup1=None, soup2=None):
        self._soup1 = soup1
        self._soup2 = soup2

    # ---------- Setters ----------

    def set_soup1(self, soup):
        self._soup1 = soup

    def set_soup2(self, soup):
        self._soup2 = soup

    def set_soups(self, soup1, soup2):
        self._soup1 = soup1
        self._soup2 = soup2

    # ---------- Getters ----------

    @property
    def soup1(self):
        return self._soup1

    @property
    def soup2(self):
        return self._soup2

    # ---------- Estado ----------

    def is_ready(self):
        return self._soup1 is not None and self._soup2 is not None

    # =========================
    # Análisis estructural
    # =========================

    def extract_structure(self, soup):
        structure = {}

        def walk(tag, depth=0):
            fp = structural_fingerprint(tag, depth)
            if not fp:
                return

            structure.setdefault(fp, []).append(
                children_fingerprints(tag, depth)
            )

            for child in tag.children:
                if getattr(child, "name", None):
                    walk(child, depth + 1)

        walk(soup.body)
        return structure

    def compare_structures(self):
        if not self.is_ready():
            raise RuntimeError("Both soup1 and soup2 must be set")

        struct1 = self.extract_structure(self._soup1)
        struct2 = self.extract_structure(self._soup2)

        dynamic_candidates = []

        for key in set(struct1) & set(struct2):
            if struct1[key] != struct2[key]:
                dynamic_candidates.append(key)

        return dynamic_candidates

    # =========================
    # Filtros de relevancia
    # =========================

    def is_relevant_candidate(self, tag, classes, depth):
        if not classes:
            return False
        if tag not in {"div", "section", "article"}:
            return False
        if depth < 2 or depth > 9:
            return False
        return True

    # =========================
    # Firma semántica
    # =========================

    def semantic_signature(self, tag, max_depth=3, depth=0):
        if depth > max_depth:
            return None

        if not tag.name or tag.name in IGNORED_TAGS:
            return None

        is_semantic = (
            tag.name in SEMANTIC_TAGS or
            bool(tag.get("class"))
        )

        children_signatures = []

        for child in tag.children:
            if getattr(child, "name", None):
                sig = self.semantic_signature(child, max_depth, depth + 1)
                if sig:
                    children_signatures.append(sig)

        if not is_semantic and len(children_signatures) == 1:
            return children_signatures[0]

        return (
            tag.name,
            tuple(sorted(tag.get("class", [])[:2])),
            tuple(children_signatures)
        )

    def item_fingerprint(self, tag):
        return self.semantic_signature(tag)

    # =========================
    # Helpers DOM
    # =========================

    def extract_child_patterns(self, tag):
        patterns = []

        for child in tag.children:
            if getattr(child, "name", None):
                if child.name in IGNORED_TAGS:
                    continue
                patterns.append(self.item_fingerprint(child))

        return Counter(patterns)

    def extract_repeated_patterns(
        self,
        child_counter,
        min_repetitions=2,
        coverage_threshold=0.6
    ):
        total = sum(child_counter.values())
        if total == 0:
            return {}

        repeated = {
            pattern: count
            for pattern, count in child_counter.items()
            if count >= min_repetitions
        }

        if not repeated:
            return {}

        coverage = sum(repeated.values()) / total

        if coverage >= coverage_threshold:
            return repeated

        return {}

    def find_matching_children(self, container, target_signature):
        matches = []

        for child in container.children:
            if getattr(child, "name", None):
                if self.semantic_signature(child) == target_signature:
                    matches.append(child)

        return matches

    def find_real_nodes(self, soup, target_fp):
        tag_name, classes, depth = target_fp
        results = []

        def walk(tag, current_depth=0):
            if current_depth > MAX_DEPTH:
                return

            if (
                tag.name == tag_name and
                normalize_classes(tag) == classes and
                current_depth == depth
            ):
                results.append(tag)

            for child in tag.children:
                if getattr(child, "name", None):
                    walk(child, current_depth + 1)

        walk(soup.body)
        return results
    
    def extract_mixed_repetition(
        self,
        child_counter,
        min_repetitions=2,
        coverage_threshold=0.6
    ):
        total = sum(child_counter.values())
        if total == 0:
            return {}

        repeated = {
            pattern: count
            for pattern, count in child_counter.items()
            if count >= min_repetitions
        }

        if not repeated:
            return {}

        coverage = sum(repeated.values()) / total

        if 0 < coverage < coverage_threshold:
            return repeated

        return {}

    def container_complexity(self, child_counter):
        total = sum(child_counter.values())
        unique = len(child_counter)
        return {
            "total_children": total,
            "unique_children": unique
        }


    # =========================
    # Clasificador: Dominantes
    # =========================

    def _classify_dominant(self, fp):
        tag, classes, depth = fp

        if not self.is_relevant_candidate(tag, classes, depth):
            return []

        nodes = self.find_real_nodes(self._soup1, fp)
        if not nodes:
            return []

        node = nodes[0]

        child_patterns = self.extract_child_patterns(node)
        repeated_patterns = self.extract_repeated_patterns(child_patterns)

        if not repeated_patterns:
            return []

        total_children = sum(child_patterns.values())

        sorted_groups = sorted(
            repeated_patterns.items(),
            key=lambda x: x[1],
            reverse=True
        )

        dominant_signature, dominant_count = sorted_groups[0]
        dominance_ratio = dominant_count / total_children

        if dominance_ratio < DOMINANCE_THRESHOLD:
            return []

        if len(sorted_groups) > 1:
            second_ratio = sorted_groups[1][1] / total_children
            if second_ratio >= (1 - DOMINANCE_THRESHOLD):
                return []

        matched_nodes = self.find_matching_children(node, dominant_signature)
        if not matched_nodes:
            return []

        representative = matched_nodes[0]

        return [{
            "container": build_css_selector(tag, classes),
            "items": [{
                "selector": "> " + build_css_selector(
                    representative.name,
                    normalize_classes(representative)
                ),
                "signature": dominant_signature,
                #"signature": signature_id(dominant_signature),
                "count": dominant_count,
                "coverage": round(dominance_ratio, 2)
            }],
            "type": "dominant"
        }]
    
    # =========================
    # Clasificador: Compuestos
    # =========================

    def _classify_composed(self, fp):
        tag, classes, depth = fp

        if not self.is_relevant_candidate(tag, classes, depth):
            return []

        nodes = self.find_real_nodes(self._soup1, fp)
        if not nodes:
            return []

        node = nodes[0]

        child_patterns = self.extract_child_patterns(node)
        repeated = self.extract_repeated_patterns(child_patterns)

        # un solo grupo no es compuesto
        if len(repeated) < 2:
            return []

        total_children = sum(child_patterns.values())

        # calcular coberturas
        coverages = {
            signature: count / total_children
            for signature, count in repeated.items()
        }

        # si alguno es dominante → no es compuesto
        if any(cov >= DOMINANCE_THRESHOLD for cov in coverages.values()):
            return []

        items = []

        for signature, count in repeated.items():
            matched_nodes = self.find_matching_children(node, signature)
            if not matched_nodes:
                continue

            representative = matched_nodes[0]

            selector = "> " + build_css_selector(
                representative.name,
                normalize_classes(representative)
            )

            items.append({
                "selector": selector,
                "signature": signature,
                #"signature": signature_id(signature),
                "count": count,
                "coverage": round(count / total_children, 2)
            })

        if len(items) < 2:
            return []

        return [{
            "container": build_css_selector(tag, classes),
            "items": items,
            "type": "composed"
        }]
    
    # =========================
    # Clasificador: Mixtos
    # =========================

    def _classify_mixed(self, fp):
        tag, classes, depth = fp

        if not self.is_relevant_candidate(tag, classes, depth):
            return []

        nodes = self.find_real_nodes(self._soup1, fp)
        if not nodes:
            return []

        node = nodes[0]

        child_patterns = self.extract_child_patterns(node)

        mixed_patterns = self.extract_mixed_repetition(child_patterns)
        if not mixed_patterns:
            return []

        total_children = sum(child_patterns.values())
        items = []

        for signature, count in mixed_patterns.items():
            matched_nodes = self.find_matching_children(node, signature)
            if not matched_nodes:
                continue

            representative = matched_nodes[0]

            selector = "> " + build_css_selector(
                representative.name,
                normalize_classes(representative)
            )

            items.append({
                "selector": selector,
                "signature": signature,
                #"signature": signature_id(signature),
                "count": count,
                "coverage": round(count / total_children, 2)
            })

        if not items:
            return []

        return [{
            "container": build_css_selector(tag, classes),
            "items": items,
            "type": "mixed"
        }]

    # =========================
    # Clasificador: No repetitivos
    # =========================

    def _classify_non_repetitive(self, fp):
        tag, classes, depth = fp

        if not self.is_relevant_candidate(tag, classes, depth):
            return []

        nodes = self.find_real_nodes(self._soup1, fp)
        if not nodes:
            return []

        node = nodes[0]

        child_patterns = self.extract_child_patterns(node)

        # Si hay repetición, no es no-repetitivo
        if self.extract_repeated_patterns(child_patterns):
            return []

        if self.extract_mixed_repetition(child_patterns):
            return []

        metrics = self.container_complexity(child_patterns)

        # Filtro de ruido
        if metrics["total_children"] < 3:
            return []

        return [{
            "container": build_css_selector(tag, classes),
            "type": "non_repetitive",
            "metrics": metrics
        }]


    # =========================
    # Orquestador
    # =========================

    def classify_dynamic_containers(self):
        dynamic_nodes = self.compare_structures()
        results = []

        for fp in dynamic_nodes:
            results.extend(self._classify_dominant(fp))
            results.extend(self._classify_composed(fp))
            results.extend(self._classify_mixed(fp))
            results.extend(self._classify_non_repetitive(fp))

        return results
    
    # =========================
    #  Detector de Variables
    # =========================
    def detect_variables(self, classifications, max_depth=3, min_text_length=15):
        """
        Analiza las clasificaciones obtenidas para extraer campos variables.
        """
        detected = []
        for entry in classifications:
            c_sel = entry["container"]
            
            # --- Caso Repetitivos ---
            if entry["type"] in ["dominant", "composed", "mixed"]:
                container_node = self.soup1.select_one(c_sel)
                if not container_node: continue

                for item_desc in entry.get("items", []):
                    sel = item_desc["selector"]
                    if sel.startswith(">"): sel = ":scope " + sel
                    nodes = container_node.select(sel)
                    if len(nodes) < 2: continue

                    found = _detect_in_repetitive_group(nodes, max_depth, min_text_length)
                    for v in found:
                        detected.append({
                            **v, 
                            "container": c_sel, 
                            "item_selector": item_desc["selector"],
                            "signature": item_desc.get("signature"), 
                            "scope": "repetitive"
                        })
            
            # --- Caso No Repetitivos (Estables entre archivos) ---
            elif entry["type"] == "non_repetitive":
                node1 = self.soup1.select_one(c_sel)
                node2 = self.soup2.select_one(c_sel)
                
                if node1 and node2:
                    cands1 = extract_value_candidates(node1, max_depth, min_text_length)
                    cands2 = extract_value_candidates(node2, max_depth, min_text_length)
                    
                    idx1 = {(c["path"], c["type"], c.get("attribute")): c for c in cands1}
                    idx2 = {(c["path"], c["type"], c.get("attribute")): c for c in cands2}

                    for key in idx1.keys() & idx2.keys():
                        val1 = _read_value(idx1[key])
                        val2 = _read_value(idx2[key])
                        if val1 != val2:
                            path, vtype, attr = key
                            detected.append({
                                "path": path, "type": vtype, "attribute": attr,
                                "variation": "inter-sessions", "container": c_sel, "scope": "stable"
                            })
        return detected