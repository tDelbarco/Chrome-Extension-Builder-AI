from collections import Counter
import hashlib
from bs4 import BeautifulSoup

#=========================
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
                "signature": signature_id(dominant_signature),
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
                "signature": signature_id(signature),
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
                "signature": signature_id(signature),
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
